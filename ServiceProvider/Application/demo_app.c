/*
  Needed for defining integer range, eg. INT_MAX
*/
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
  Needed for untrusted enclave ocall interface
*/
#include "demo_enclave_u.h"

/*
  Needed for some data structures
*/
#include "demo_app.h"

/*
  Needed to perform some utility functions
*/
#include "utils.h"

/*
  Needed for data structures related to attestation_result
*/
#include "remote_attestation_result.h"

/*
  Needed to create enclave and do ecall
*/
#include "sgx_urts.h"

/*
  Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
*/
#include "sgx_ukey_exchange.h"

/*
  Needed to query extended epid group id.
*/
#include "sgx_uae_service.h"

#define TRUSTED_BROKER_ADDRESS "127.0.0.1"
#define MAIN_PORT 8001
#define HEARTBEAT_PORT 8002


#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

/*
  define the enclave id
*/
static sgx_enclave_id_t global_eid = 0;

/*
 * define heartbeat thread function
 */
void *heartbeat_event_loop(void *hb_socket){

  int ret = 0;
  sgx_status_t status = SGX_SUCCESS;
  uint32_t hb_status = 0;

  int *hb_socket_fd = (int *)hb_socket;

  pkg_header_t *hb_resp = NULL;
  sp_aes_gcm_data_t *p_enc_hb = NULL;

  bool end_loop = false;
  do{

    ret = hb_network_sync(*hb_socket_fd, &hb_resp);

    if(ret !=0 || !hb_resp){
      fprintf(stderr, "\nError, receiving heartbeat signal failed [%s].", __FUNCTION__);
      exit(0);
    }

    p_enc_hb = (sp_aes_gcm_data_t*)((uint8_t*)hb_resp + sizeof(pkg_header_t));

    ret = ecall_heartbeat_process(global_eid, &status, p_enc_hb->payload, p_enc_hb->payload_size, p_enc_hb->payload_tag, &hb_status);
    if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
      fprintf(stderr, "\nError, decrypted heartbeat using secret_share_key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x\n", __FUNCTION__, ret, status);
      exit(0);
    }

    /*
     * SUCCESS: 1
     * REVOKED: 2
     * REPLAY: 3
     */
    if(2 == hb_status){
      end_loop = true;
    }

  }while(!end_loop);
}

/*
  print error message for loading enclave
*/
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/*
  define the untrusted enclave ocall functions
*/
void ocall_print_string(const char* str){
  printf("%s", str);
}

/*
  entry of the application
*/
int SGX_CDECL main(int argc, char *argv[]){

  /*
    define result status of ecall function
  */
  int ret = 0;
  sgx_status_t status = SGX_SUCCESS;


  /*
    initialize sockets
  */
  int socket_fd;
  if( (socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
    printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(sockaddr_in));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(TRUSTED_BROKER_ADDRESS);
  servaddr.sin_port = htons(MAIN_PORT);

  if( connect(socket_fd, (struct sockaddr*)&servaddr, sizeof(sockaddr_in)) < 0 ){
    printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  int hb_socket_fd;
  if( (hb_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
    printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  struct sockaddr_in hb_servaddr;
  memset(&hb_servaddr, 0, sizeof(sockaddr_in));
  hb_servaddr.sin_family = AF_INET;
  hb_servaddr.sin_addr.s_addr = inet_addr(TRUSTED_BROKER_ADDRESS);
  hb_servaddr.sin_port = htons(HEARTBEAT_PORT);

  if( connect(hb_socket_fd, (struct sockaddr*)&hb_servaddr, sizeof(sockaddr_in)) < 0 ){
    printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  /*
    define msg0 - msg3 and the attestation result message
  */
  pkg_header_t *p_msg0_full = NULL;
  pkg_header_t *p_msg0_resp_full = NULL;
  pkg_header_t *p_msg1_full = NULL;
  pkg_header_t *p_msg2_full = NULL;
  pkg_header_t *p_msg3_full = NULL;
  sgx_ra_msg3_t *p_msg3 = NULL;
  pkg_header_t *p_att_result_msg_full = NULL;

  pkg_header_t *key_req = NULL;
  pkg_header_t *key_resp = NULL;
  sp_certificate_t * hcp = NULL;
  sp_aes_gcm_data_t *p_enc_dev_keys = NULL;

  pkg_header_t *dev_0_offset_0_data_resp = NULL;
  pkg_header_t *dev_0_offset_1_data_resp = NULL;
  pkg_header_t *dev_0_offset_2_data_resp = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_0_data = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_1_data = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_2_data = NULL;

  uint32_t perform_sum_fun_result = -1;

  pthread_t hb_id;
  int hb_freq = 2;
  void *hb_ret;

  /*
    define retry parameters
  */
  int enclave_lost_retry_time = 1;
  int busy_retry_time = 4;

  /*
    define remote attestation context
  */
  sgx_ra_context_t context = INT_MAX;

  /*
    define the output source file
  */
  FILE *OUTPUT = stdout;

  fprintf(OUTPUT, "\n***Starting Remote Attestation Functionality***\n\n");
  sleep(2);

  {
    /*
      preparation for remote attestation by configuring extended epid group id - msg0.
    */

    uint32_t extended_epid_group_id = 0;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if(SGX_SUCCESS != ret){
      ret = -1;
      fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].", __FUNCTION__);
      return ret;
    }
    fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.\n");

    p_msg0_full = (pkg_header_t*) malloc(sizeof(pkg_header_t) + sizeof(uint32_t));

    if(NULL == p_msg0_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(uint32_t);

    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(pkg_header_t)) = extended_epid_group_id;
    {

      fprintf(OUTPUT, "\nMSG0 body generated -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

    }

    ret = ra_network_send_receive(socket_fd, p_msg0_full, &p_msg0_resp_full);
    if (ret != 0)
    {
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
            "[%s].", __FUNCTION__);
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nSent msg0 to remote trusted broker.\n");
    sleep(1);

  }

  /*
    Remote attestation will be initiated the trusted broker challengs the demo_app of if the demo_app detects it doesn't have the credentials (shared secrets) from a previous attestation required for secure communication with the trusted broker
  */

  {

    do{
      /*
        demo_app initializes its enclave
       */
      if(initialize_enclave() < 0){
        ret = -1;
        fprintf(OUTPUT, "\nError, enclave initialization Failed [%s].", __FUNCTION__);
        goto CLEANUP;
      }

      fprintf(OUTPUT, "\nEncalve initialization success.\n");
      sleep(1);

      ret = ecall_init_ra(global_eid, &status, false, &context);

    }while(SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if(SGX_SUCCESS != ret || status)
    {
      ret = -1;
      fprintf(OUTPUT, "\nError, call ecall_init_ra fail [%s].",
              __FUNCTION__);
      goto CLEANUP;
    }

    fprintf(OUTPUT, "\nRemote attestation initialization success.\n");
    sleep(1);
  }

  /*
    msg1
  */
  {
    p_msg1_full = (pkg_header_t*)
                  malloc(sizeof(pkg_header_t) + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);

    do{
      ret = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga, (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(pkg_header_t)));
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(SGX_SUCCESS != ret)
    {
      ret = -1;
      fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
              __FUNCTION__);
      goto CLEANUP;
    }
    else
    {
      fprintf(OUTPUT, "\nMSG1 body generated -\n");
      PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
    }

    ret = ra_network_send_receive(socket_fd, p_msg1_full, &p_msg2_full);

    if(ret != 0 || !p_msg2_full){
      fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed [%s].", __FUNCTION__);

    }else{
      // Successfully sent msg1 and received a msg2 back.
      // Time now to check msg2.
      if(TYPE_RA_MSG2 != p_msg2_full->type){

        fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. [%s].", __FUNCTION__);
        goto CLEANUP;

      }

      fprintf(OUTPUT, "\nSent MSG1 successfully. Received the following MSG2:\n");
      sleep(1);
      PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, sizeof(pkg_header_t) + p_msg2_full->size);
      fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
      PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

    }
  }

  /*
    msg3
   */
  {
    sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(pkg_header_t));

    uint32_t msg3_size = 0;

    busy_retry_time = 2;
    // The demo_app now calls uKE sgx_ra_proc_msg2,
    // The demo_app is responsible for freeing the returned p_msg3!!
    do
    {
      ret = sgx_ra_proc_msg2(context,
                         global_eid,
                         sgx_ra_proc_msg2_trusted,
                         sgx_ra_get_msg3_trusted,
                         p_msg2_body,
                         p_msg2_full->size,
                         &p_msg3,
                         &msg3_size);
    }while(SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(!p_msg3){
      fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
      ret = -1;
      goto CLEANUP;
    }

    if(SGX_SUCCESS != (sgx_status_t)ret){
      fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. ret = 0x%08x [%s].", ret, __FUNCTION__);
      ret = -1;
      goto CLEANUP;
    }

    fprintf(OUTPUT, "\nMSG3 body generated- \n");
    PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (pkg_header_t*)malloc(
                   sizeof(pkg_header_t) + msg3_size);

    if(NULL == p_msg3_full)
    {
      ret = -1;
      goto CLEANUP;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;

    memcpy((sgx_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(pkg_header_t)), p_msg3, msg3_size);

  }

  /*
    result attestation msg
  */
  {
    ret = ra_network_send_receive(socket_fd, p_msg3_full, &p_att_result_msg_full);

    if(ret !=0 || !p_att_result_msg_full){
      ret = -1;
      fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
      goto CLEANUP;
    }

    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type){
      ret = -1;
      fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message received was NOT of type att_msg_result. Type = %d. [%s].", p_att_result_msg_full->type, __FUNCTION__);
      goto CLEANUP;
    }

    fprintf(OUTPUT, "\nSent MSG3 successfully. Received the following attestation result (MSG4).\n");
    sleep(1);

    PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);
    fprintf(OUTPUT, "\nA more descriptive ATTESTATION RESULT: \n");
    PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_att_result_msg_full);

  /*
    verify the attestation result
  */

    // Check the MAC using MK on the attestation result message.
    // The format of the attestation result message is demo_app specific.
    // This is a simple form for demonstration. In a real product,
    // the demo_app may want to communicate more information.
    sample_ra_att_result_msg_t *p_att_result_msg_body = (sample_ra_att_result_msg_t*)((uint8_t*)p_att_result_msg_full + sizeof(pkg_header_t));

    ret = ecall_verify_result_mac(global_eid, &status, context, (uint8_t*)&p_att_result_msg_body->platform_info_blob, sizeof(ias_platform_info_blob_t), (uint8_t*)&p_att_result_msg_body->mac, sizeof(sgx_mac_t));

    if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
      ret = -1;
      fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result message MK based cmac failed in [%s].", __FUNCTION__);
      goto CLEANUP;
    }

    bool attestation_passed = true;
    // Check the attestation result for pass or fail.
    // Whether attestation passes or fails is a decision made by the ISV Server.
    // When the ISV server decides to trust the enclave, then it will return success.
    // When the ISV server decided to not trust the enclave, then it will return failure.
    if(0 != p_att_result_msg_full->reserved[0] || 0 != p_att_result_msg_full->reserved[1]){
      fprintf(OUTPUT, "\nError, attestation result message MK based cmac failed in [%s].", __FUNCTION__);
      attestation_passed = false;
    }

    if(attestation_passed){

      ret = ecall_put_secrets(global_eid, &status,
                            context, p_att_result_msg_body->secret.payload, p_att_result_msg_body->secret.payload_size, p_att_result_msg_body->secret.payload_tag);
      if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
        fprintf(OUTPUT, "\nError, attestation result message secret using SK based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
        goto CLEANUP;
      }
    }
    fprintf(OUTPUT, "\nSecret successfully received from trusted broker.");
    fprintf(OUTPUT, "\nRemote attestation success!\n\n");
    sleep(1);
  }


CLEANUP:

  if(INT_MAX != context){
    int ret_save = ret;
    ret = ecall_close_ra(global_eid, &status, context);
    if(SGX_SUCCESS != ret || status){
      ret = -1;
      fprintf(OUTPUT, "\nError, call ecall_close_ra fail() [%s].", __FUNCTION__);
    }
    else{
      // enclave_ra_close was successful, let's restore the value that
      // led us to this point in the code.
      ret = ret_save;
    }
    fprintf(OUTPUT, "\nCall ecall_close_ra() success.");
  }

  fprintf(OUTPUT, "\n\n***Starting Sealing Secrets Functionality***\n\n");
  sleep(2);
  /*
    define seal log parameters
  */
  /* equal to sgx_calc_sealed_data_size(0,sizeof(replay_protected_pay_load))) in ss.c
  */
#define SEALED_REPLAY_PROTECTED_PAY_LOAD_SIZE 624
  uint32_t sealed_activity_log_length = SEALED_REPLAY_PROTECTED_PAY_LOAD_SIZE;
  uint8_t  sealed_activity_log[sealed_activity_log_length];

  sgx_ps_cap_t ps_cap;
  memset(&ps_cap, 0, sizeof(sgx_ps_cap_t));
  ret = sgx_get_ps_cap(&ps_cap);
  if(SGX_SUCCESS != ret){
    fprintf(OUTPUT, "\nCannot get platform service capability failed in [%s], error code = 0x%0x\n", __FUNCTION__, ret);
    ret = -1;
    goto FINAL;
  }
  if(!SGX_IS_MONOTONIC_COUNTER_AVAILABLE(ps_cap)){
    fprintf(OUTPUT, "\nMonotonic counter is not supported failed in [%s], error code = 0x%0x\n", __FUNCTION__, SGX_ERROR_SERVICE_UNAVAILABLE);
    ret = -1;
    goto FINAL;
  }


  ret = ecall_create_sealed_policy(global_eid, &status, (uint8_t *)sealed_activity_log, sealed_activity_log_length);
  if(SGX_SUCCESS != ret){
    fprintf(OUTPUT, "\nCall ecall_create_sealed_policy failed in [%s], error code = 0x%0x\n", __FUNCTION__, ret);
    ret = -1;
    goto FINAL;
  }
  if(SGX_SUCCESS != status){
    fprintf(OUTPUT, "\nCannot create_sealed_policy failed in [%s], error code = 0x%0x\n", __FUNCTION__, status);
    ret = -1;
    goto FINAL;
  }

  fprintf(OUTPUT, "\nSecrets sealed in sealed_activity_log successfully\n");
  sleep(1);

  ret = ecall_perform_sealed_policy(global_eid, &status, (uint8_t *)sealed_activity_log, sealed_activity_log_length);
  if(SGX_SUCCESS != ret){
    fprintf(OUTPUT, "\nCall ecall_perform_sealed_policy failed in [%s], error code = 0x%0x\n", __FUNCTION__, ret);
    ret = -1;
    goto FINAL;
  }
  if(SGX_SUCCESS != status){
    fprintf(OUTPUT, "\nCannot perform_sealed_policy failed in [%s], error code = 0x%0x\n", __FUNCTION__, status);
    ret = -1;
    goto FINAL;
  }

  fprintf(OUTPUT, "\nSecrets sealed recovered from sealed_activity_log successfully\n");
  sleep(1);


  fprintf(OUTPUT, "\n\n***Starting Key Request Functionality***\n\n");
  sleep(2);

  hcp = (sp_certificate_t *)malloc(sizeof(sp_certificate_t));
  memset(hcp, 0, sizeof(sp_certificate_t));
  hcp->id = 1;
  hcp->sig = {0};

  key_req = (pkg_header_t*)malloc(
                 sizeof(pkg_header_t) + sizeof(sp_certificate_t));

  if(NULL == key_req)
  {
    ret = -1;
  }
  key_req->type = TYPE_KEY_REQ;
  key_req->size = sizeof(sp_certificate_t);

  memcpy((sp_certificate_t*)((uint8_t*)key_req + sizeof(pkg_header_t)), hcp, sizeof(sp_certificate_t));

  fprintf(OUTPUT, "\nKey request package generated\n");

  ret = kq_network_send_receive(socket_fd, key_req, &key_resp);

  if(ret !=0 || !key_resp){
    ret = -1;
    fprintf(OUTPUT, "\nError, sending key request failed [%s].", __FUNCTION__);
  }

  fprintf(OUTPUT, "\nSent key request successfully. Received device keys\n");
  sleep(1);

  p_enc_dev_keys = (sp_aes_gcm_data_t*)((uint8_t*)key_resp + sizeof(pkg_header_t));

  ret = ecall_put_keys(global_eid, &status, p_enc_dev_keys->payload, p_enc_dev_keys->payload_size, p_enc_dev_keys->payload_tag);
  if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
    fprintf(OUTPUT, "\nError, encrypted key set secret using secret_share_key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
    goto FINAL;
  }

  fprintf(OUTPUT, "\nDevice keys loaded in the enclave.\n");
  sleep(1);

  /*
    start heartbeat mechanism for the enclave, or no calculation ecall functions can be executed
  */

  printf("\n\n***Starting Heartbeat Functionality***\n\n");
  sleep(2);

  pthread_create(&hb_id, NULL, heartbeat_event_loop, (void *)&hb_socket_fd);


  // fprintf(OUTPUT, "\n\n***Starting Data Request Functionality***\n");
  //
  // fprintf(OUTPUT, "\nRequest data from the cloud storage.\n");
  //
  // fprintf(OUTPUT, "\nDev0_0\n");
  // ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 0, &dev_0_offset_0_data_resp);
  //
  // if(ret !=0 || !dev_0_offset_0_data_resp){
  //   ret = -1;
  //   fprintf(OUTPUT, "\nError, dev 0 offset 0 data retrieve failed [%s].", __FUNCTION__);
  // }
  //
  // fprintf(OUTPUT, "\nDev0_1\n");
  // p_enc_dev_0_offset_0_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_0_data_resp + sizeof(pkg_header_t));
  //
  // ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 1, &dev_0_offset_1_data_resp);
  //
  // if(ret !=0 || !dev_0_offset_1_data_resp){
  //   ret = -1;
  //   fprintf(OUTPUT, "\nError, dev 0 offset 1 data retrieve failed [%s].", __FUNCTION__);
  // }
  //
  // fprintf(OUTPUT, "\nDev0_2\n");
  // p_enc_dev_0_offset_1_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_1_data_resp + sizeof(pkg_header_t));
  //
  // ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 2, &dev_0_offset_2_data_resp);
  //
  // if(ret !=0 || !dev_0_offset_2_data_resp){
  //   ret = -1;
  //   fprintf(OUTPUT, "\nError, dev 0 offset 2 data retrieve failed [%s].", __FUNCTION__);
  // }
  //
  // p_enc_dev_0_offset_2_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_2_data_resp + sizeof(pkg_header_t));
  //
  // printf("\n***Perform Statistics Function Over Dev0_0, Dev0_1***\n\n");
  //
  // ret = ecall_perform_statistics(global_eid, &status, p_enc_dev_0_offset_0_data->payload, p_enc_dev_0_offset_0_data->payload_size, p_enc_dev_0_offset_0_data->payload_tag, 0,  p_enc_dev_0_offset_1_data->payload, p_enc_dev_0_offset_1_data->payload_size, p_enc_dev_0_offset_1_data->payload_tag, 0, &perform_sum_fun_result);
  //
  //
  // printf("\nthe final sum value returned from the enclave is: %d\n\n", perform_sum_fun_result);
  //
  //
  // for(int c=1; c <= 15; c++){
  //   printf("\n\nMain thread: %d\n", c);
  //
  //   printf("\n***Perform Statistics Function Over Dev0_0, Dev0_1***\n\n");
  //
  //   ret = ecall_perform_statistics(global_eid, &status, p_enc_dev_0_offset_0_data->payload, p_enc_dev_0_offset_0_data->payload_size, p_enc_dev_0_offset_0_data->payload_tag, 0,  p_enc_dev_0_offset_1_data->payload, p_enc_dev_0_offset_1_data->payload_size, p_enc_dev_0_offset_1_data->payload_tag, 0, &perform_sum_fun_result);
  //
  //
  //   printf("\nthe final sum value returned from the enclave is: %d\n\n", perform_sum_fun_result);
  //
  //   sleep(3);
  // }

FINAL:

  /*
    when an encalve is stoped, you need end hearbeat mechanism exploitly by revoking ecall_end_heartbeat()
  */
  // ecall_end_heartbeat(global_eid, &status);

  if (pthread_join(hb_id, &hb_ret) != 0) {
    perror("\nCall pthread_join() error.\n");
  }

  close(socket_fd);

  sgx_destroy_enclave(global_eid);

  printf("\n\nInfo: Enclave Successfully Retrurned. \n");

  printf("Enter a character before exit ... \n");
  getchar();
  pthread_exit(NULL);
  return ret;
}
