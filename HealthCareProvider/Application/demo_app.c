/*
  Needed for defining integer range, eg. INT_MAX
*/
#include <limits.h>

#include <pthread.h>

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
#include "ThirdPartyLibrary/key_management.h"

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

// #include <time.h>
//
// #include "evaluation.h"
//
// #define RESULT_FILE "./results.txt"
// #define BASELINE_RESULT_FILE "./baseline_results.txt"

// #define SAMPLE_SP_IV_SIZE        12

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

/*
  define the enclave id
*/
static sgx_enclave_id_t global_eid = 0;

void *heartbeat_event_loop(void *freq){

  int *hb_freq = (int *)freq;

  int ret = 0;
  sgx_status_t status = SGX_SUCCESS;

  hb_samp_package_header_t *hb_resp = NULL;
  sp_aes_gcm_data_t *p_enc_hb = NULL;

  for(int i = 0; i < 20; i++){

    ret = hb_network_send_receive("http://demo_testing.cnsr.vt.edu/", &hb_resp);

    if(ret !=0 || !hb_resp){
      ret = -1;
      fprintf(stderr, "\nError, receiving heartbeat signal failed [%s].", __FUNCTION__);
    }

    p_enc_hb = (sp_aes_gcm_data_t*)((uint8_t*)hb_resp + sizeof(hb_samp_package_header_t));

    ret = ecall_heartbeat_process(global_eid, &status, p_enc_hb->payload, p_enc_hb->payload_size, p_enc_hb->payload_tag);
    if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
      fprintf(stderr, "\nError, decrypted heartbeat using secret_share_key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
    }

    sleep(*hb_freq);
  }
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
void ocall_print(const char* str){
  printf("%s\n", str);
}

void ocall_print_int(int num){
  printf("The number is: %d\n", num);
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
    define msg0 - msg3 and the attestation result message
  */
  ra_samp_request_header_t *p_msg0_full = NULL;
  ra_samp_response_header_t *p_msg0_resp_full = NULL;
  ra_samp_request_header_t *p_msg1_full = NULL;
  ra_samp_response_header_t *p_msg2_full = NULL;
  ra_samp_request_header_t *p_msg3_full = NULL;
  sgx_ra_msg3_t *p_msg3 = NULL;
  ra_samp_response_header_t *p_att_result_msg_full = NULL;

  kd_samp_package_header_t *key_req = NULL;
  kd_samp_package_header_t *key_resp = NULL;
  hcp_samp_certificate_t * hcp = NULL;
  sp_aes_gcm_data_t *p_enc_dev_keys = NULL;

  du_samp_package_header_t *dev_0_offset_0_data_resp = NULL;
  du_samp_package_header_t *dev_0_offset_1_data_resp = NULL;
  du_samp_package_header_t *dev_0_offset_2_data_resp = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_0_data = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_1_data = NULL;
  sp_aes_gcm_data_t *p_enc_dev_0_offset_2_data = NULL;

  uint32_t perform_sum_fun_result = -1;

  pthread_t hb_id;
  int hb_loop = 20;
  int hb_freq = 2;

  // double sum_time = 0.0;
  // double average_time = 0.0;
  // uint32_t result_temp = 0;
  // double mean = 0.0;
  // double variance = 0.0;
  //
  // uint8_t evaluation_data_1[8] = {
  //   0xf5, 0x5b, 0x56, 0xf0, 0xac, 0x7f, 0x78, 0x39
  // };
  //
  // uint8_t evaluation_data_2[8] = {
  //   0x39, 0x85, 0x37, 0xfe, 0xad, 0x1f, 0xc7, 0x59
  // };
  //
  // #define FILE_NUM 100000
  // enc_file eval_files[FILE_NUM] = {0};
  // uint8_t ssk[16] = {
  //   0x72, 0xee, 0x30, 0xb0,
  //   0x1d, 0xd9, 0x11, 0x38,
  //   0x24, 0x11, 0x14, 0x3a,
  //   0xe2, 0xaa, 0x60, 0x38
  // };
  // uint8_t aes_gcm_iv[12] = {0};

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
    define verification parameters
  */
  int32_t verify_index = -1;
  int32_t verification_samples = sizeof(msg1_samples)/sizeof(msg1_samples[0]);
  #define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && verify_index <= verification_samples)
  #define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

  /*
    define the output source file
  */
  FILE *OUTPUT = stdout;

  if(argc > 1){
    verify_index = atoi(argv[1]);
    if(VERIFICATION_INDEX_IS_VALID()){
      fprintf(OUTPUT, "\nVerifying precomputed attestation messages using precomputed values# %d\n", verify_index);
    }else{
      fprintf(OUTPUT, "\nValid invocations are:\n");
      fprintf(OUTPUT, "\n\t./demo_app\n");
      fprintf(OUTPUT, "\n\t./demo_app <verification index>\n");
      fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
              verification_samples);
      fprintf(OUTPUT, "\nUsing a verification index uses precomputed messages to assist debugging the remote attestation trusted broker.\n");
      return -1;
    }
  }

  /*
    preparation for remote attestation by configuring extended epid group id - msg0.
  */

  {
    uint32_t extended_epid_group_id = 0;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if(SGX_SUCCESS != ret){
      ret = -1;
      fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].", __FUNCTION__);
      return ret;
    }
    fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.\n");

    p_msg0_full = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t) + sizeof(uint32_t));

    if(NULL == p_msg0_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(uint32_t);

    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
    {

      fprintf(OUTPUT, "\nMSG0 body generated -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

    }

    fprintf(OUTPUT, "\nSending msg0 to remote attestation trusted broker.\n");

    ret = ra_network_send_receive("http://demo_testing.cnsr.vt.edu/", p_msg0_full, &p_msg0_resp_full);
    if (ret != 0)
    {
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
            "[%s].", __FUNCTION__);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");
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

      ret = ecall_init_ra(global_eid, &status, false, &context);

    }while(SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if(SGX_SUCCESS != ret || status)
    {
      ret = -1;
      fprintf(OUTPUT, "\nError, call ecall_init_ra fail [%s].",
              __FUNCTION__);
      goto CLEANUP;
    }
    fprintf(OUTPUT, "\nCall ecall_init_ra success.\n");

  }

  /*
    msg1
  */
  {
    p_msg1_full = (ra_samp_request_header_t*)
                  malloc(sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);

    do{
      ret = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga, (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_samp_request_header_t)));
      sleep(3); // Wait 3s between retries
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
      fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

      fprintf(OUTPUT, "\nMSG1 body generated -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
    }

    if(VERIFICATION_INDEX_IS_VALID()){

      // memcpy_s(p_msg1_full->body, p_msg1_full->size, msg1_samples[GET_VERIFICATION_ARRAY_INDEX()], p_msg1_full->size);

      memcpy(p_msg1_full->body, msg1_samples[GET_VERIFICATION_ARRAY_INDEX()], p_msg1_full->size);

      fprintf(OUTPUT, "\nInstead of using the recently generated MSG1, "
                      "we will use the following precomputed MSG1 -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

    }


    // The demo_app sends msg1 to the trusted broker to get msg2,
    // msg2 needs to be freed when no longer needed.
    // The demo_app decides whether to use linkable or unlinkable signatures.
    fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider. Expecting msg2 back.\n");

    ret = ra_network_send_receive("http://demo_testing.cnsr.vt.edu/", p_msg1_full, &p_msg2_full);

    if(ret != 0 || !p_msg2_full){
      fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed [%s].", __FUNCTION__);

      if(VERIFICATION_INDEX_IS_VALID()){
        fprintf(OUTPUT, "\nBecause we are in verification mode we will ignore this error.\n");
        fprintf(OUTPUT, "\nInstead, we will pretend we received the following MSG2 - \n");

        SAFE_FREE(p_msg2_full);
        ra_samp_response_header_t* precomputed_msg2 =
            (ra_samp_response_header_t*)msg2_samples[
                GET_VERIFICATION_ARRAY_INDEX()];
        const size_t msg2_full_size = sizeof(ra_samp_response_header_t)
                                      +  precomputed_msg2->size;
        p_msg2_full =
            (ra_samp_response_header_t*)malloc(msg2_full_size);
        if(NULL == p_msg2_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        // memcpy_s(p_msg2_full, msg2_full_size, precomputed_msg2,
        //          msg2_full_size);
        memcpy(p_msg2_full, precomputed_msg2,
                 msg2_full_size);

        PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                         sizeof(ra_samp_response_header_t)
                         + p_msg2_full->size);
      }else{
        goto CLEANUP;
      }
    }else{
      // Successfully sent msg1 and received a msg2 back.
      // Time now to check msg2.
      if(TYPE_RA_MSG2 != p_msg2_full->type){

        fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. [%s].", __FUNCTION__);

        if(VERIFICATION_INDEX_IS_VALID()){
          fprintf(OUTPUT, "\nBecause we are in verification mode we will ignore this error.");
        }
        else{
            goto CLEANUP;
        }
      }

      fprintf(OUTPUT, "\nSent MSG1 to remote attestation trusted broker. Received the following MSG2:\n");
      PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, sizeof(ra_samp_response_header_t) + p_msg2_full->size);

      fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
      PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

      if( VERIFICATION_INDEX_IS_VALID() )
      {
        // The response should match the precomputed MSG2:
        ra_samp_response_header_t* precomputed_msg2 =
            (ra_samp_response_header_t *)
            msg2_samples[GET_VERIFICATION_ARRAY_INDEX()];
        if(MSG2_BODY_SIZE !=
            sizeof(ra_samp_response_header_t) + p_msg2_full->size ||
            memcmp( precomputed_msg2, p_msg2_full,
                sizeof(ra_samp_response_header_t) + p_msg2_full->size)){

            fprintf(OUTPUT, "\nVerification ERROR. Our precomputed value for MSG2 does NOT match.\n");
            fprintf(OUTPUT, "\nPrecomputed value for MSG2:\n");
            PRINT_BYTE_ARRAY(OUTPUT, precomputed_msg2, sizeof(ra_samp_response_header_t) + precomputed_msg2->size);
            fprintf(OUTPUT, "\nA more descriptive representation of precomputed value for MSG2:\n");
            PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, precomputed_msg2);
        }else{
          fprintf(OUTPUT, "\nVerification COMPLETE. Remote attestation trusted broker generated a matching MSG2.\n");
        }
      }
    }
  }

  /*
    msg3
   */
  {
    sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(ra_samp_response_header_t));

    uint32_t msg3_size = 0;
    if( VERIFICATION_INDEX_IS_VALID())
    {
      // We cannot generate a valid MSG3 using the precomputed messages
      // we have been using. We will use the precomputed msg3 instead.
      msg3_size = MSG3_BODY_SIZE;
      p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
      if(NULL == p_msg3)
      {
          ret = -1;
          goto CLEANUP;
      }
      // memcpy_s(p_msg3, msg3_size,
      //          msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
      memcpy(p_msg3, msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
      fprintf(OUTPUT, "\nBecause MSG1 was a precomputed value, the MSG3 "
                      "we use will also be. PRECOMPUTED MSG3 - \n");
    }else{
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
      }else{
        fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
        fprintf(OUTPUT, "\nMSG3 - \n");
      }
    }

    PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (ra_samp_request_header_t*)malloc(
                   sizeof(ra_samp_request_header_t) + msg3_size);

    if(NULL == p_msg3_full)
    {
      ret = -1;
      goto CLEANUP;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;

    memcpy((sgx_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t)), p_msg3, msg3_size);

    fprintf(OUTPUT, "\nMSG3 package generated\n");

    // if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
    // {
    //   fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
    //           __FUNCTION__);
    //   ret = -1;
    //   goto CLEANUP;
    // }
  }

  /*
    result attestation msg
  */
  {
    ret = ra_network_send_receive("http://demo_testing.cnsr.vt.edu/", p_msg3_full, &p_att_result_msg_full);

    if(ret !=0 || !p_att_result_msg_full){
      ret = -1;
      fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
      goto CLEANUP;
    }

    sample_ra_att_result_msg_t *p_att_result_msg_body = (sample_ra_att_result_msg_t*)((uint8_t*)p_att_result_msg_full + sizeof(ra_samp_response_header_t));

    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type){
      ret = -1;
      fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message received was NOT of type att_msg_result. Type = %d. [%s].", p_att_result_msg_full->type, __FUNCTION__);
      goto CLEANUP;
    }else{
      fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation result message back\n.");
      if( VERIFICATION_INDEX_IS_VALID() ){
        if(ATTESTATION_MSG_BODY_SIZE != p_att_result_msg_full->size || memcmp(p_att_result_msg_full->body, attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()], p_att_result_msg_full->size) ){
          fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation result message back that did NOT match the expected value.\n");
          fprintf(OUTPUT, "\nEXPECTED ATTESTATION RESULT -");
          PRINT_BYTE_ARRAY(OUTPUT, attestation_msg_samples[GET_VERIFICATION_ARRAY_INDEX()], ATTESTATION_MSG_BODY_SIZE);
        }
      }
    }

    fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
    PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);

    if( VERIFICATION_INDEX_IS_VALID() )
    {
      fprintf(OUTPUT, "\nBecause we used precomputed values for the messages, the attestation result message will not pass further verification tests, so we will skip them.\n");
      goto CLEANUP;
    }

  /*
    verify the attestation result
  */

    // Check the MAC using MK on the attestation result message.
    // The format of the attestation result message is demo_app specific.
    // This is a simple form for demonstration. In a real product,
    // the demo_app may want to communicate more information.
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
    if(0 != p_att_result_msg_full->status[0] || 0 != p_att_result_msg_full->status[1]){
      fprintf(OUTPUT, "\nError, attestation result message MK based cmac failed in [%s].", __FUNCTION__);
      attestation_passed = false;
    }

    // The attestation result message should contain a field for the Platform
    // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
    // It is not returned in all cases, but when it is, the ISV app
    // should pass it to the blob analysis API called sgx_report_attestation_status()
    // along with the trust decision from the ISV server.
    // The ISV application will take action based on the update_info.
    // returned in update_info by the API.
    // This call is stubbed out for the sample.
    //
    // sgx_update_info_bit_t update_info;
    // ret = sgx_report_attestation_status(
    //     &p_att_result_msg_body->platform_info_blob,
    //     attestation_passed ? 0 : 1, &update_info);

    // Get the shared secret sent by the server using SK (if attestation
    // passed)

    if(attestation_passed){
      ret = ecall_put_secrets(global_eid, &status,
                            context, p_att_result_msg_body->secret.payload, p_att_result_msg_body->secret.payload_size, p_att_result_msg_body->secret.payload_tag);
      if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
        fprintf(OUTPUT, "\nError, attestation result message secret using SK based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
        goto CLEANUP;
      }
    }
    fprintf(OUTPUT, "\nSecret successfully received from server.");
    fprintf(OUTPUT, "\nRemote attestation success!\n\n");
  }

  /*
    evaluation
  */


  // for(int q = 0; q < FILE_NUM; q++){
  //   sample_rijndael128GCM_encrypt(&ssk,
  //           &evaluation_data_1[0],
  //           8,
  //           eval_files[q].payload,
  //           &aes_gcm_iv[0],
  //           SAMPLE_SP_IV_SIZE,
  //           NULL,
  //           0,
  //           &eval_files[q].payload_tag);
  //   eval_files[q].payload_size = 8;
  // }
  //
  // clock_t start, end;
  // double exe_time;
  // int v;
  //
  // for(v = 1000; v <= FILE_NUM; ){
  //   start = clock();
  //   // for(int b = 0; b < v; b++){
  //   //   ret = sgx_rijndael128GCM_decrypt(&ssk, eval_files[b].payload, eval_files[b].payload_size, &evaluation_data_2[0], &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(eval_files[b].payload_tag));
  //   //   if(SGX_SUCCESS != ret){
  //   //     fprintf(OUTPUT, "\nError, evaluation decryption using shared key based AESGCM failed in [%s]. ret = 0x%0x.", __FUNCTION__, ret);
  //   //   }
  //   // }
  //   end = clock();
  //   exe_time = (double)(end - start)/CLOCKS_PER_SEC;
  //   // printf("\nfile numbers: %d; time: %lf\n", FILE_NUM, exe_time);
  //   printf("\nwriting to baseline result file\n");
  //   write_result(BASELINE_RESULT_FILE, v, exe_time);
  //   v = v + 1000;
  // }
  //
  //
  // for(v = 1000; v <= FILE_NUM; ){
  //   start = clock();
  //   ret = ecall_evaluate_decryption(global_eid, &status, &eval_files[0].payload_size, v, v*32);
  //   end = clock();
  //   exe_time = (double)(end - start)/CLOCKS_PER_SEC;
  //   // printf("\nfile numbers: %d; time: %lf\n", FILE_NUM, exe_time);
  //   printf("\nwriting to result file\n");
  //   write_result(RESULT_FILE, v, exe_time);
  //   v = v + 1000;
  //
  //   if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
  //     fprintf(OUTPUT, "\nError, evaluation decryption using shared key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
  //   }
  // }



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

  fprintf(OUTPUT, "\n\n***Starting Key Request Functionality***\n");

  hcp = (hcp_samp_certificate_t *)malloc(sizeof(hcp_samp_certificate_t));
  memset(hcp, 0, sizeof(hcp_samp_certificate_t));
  hcp->id = 1;
  hcp->sig = {0};

  key_req = (kd_samp_package_header_t*)malloc(
                 sizeof(kd_samp_package_header_t) + sizeof(hcp_samp_certificate_t));

  if(NULL == key_req)
  {
    ret = -1;
  }
  key_req->type = TYPE_KEY_REQUEST;
  key_req->size = sizeof(hcp_samp_certificate_t);

  memcpy((hcp_samp_certificate_t*)((uint8_t*)key_req + sizeof(kd_samp_package_header_t)), hcp, sizeof(hcp_samp_certificate_t));

  fprintf(OUTPUT, "\nHealth Care Provider key request package generated\n");

  ret = kq_network_send_receive("http://demo_testing.cnsr.vt.edu/", key_req, &key_resp);

  if(ret !=0 || !key_resp){
    ret = -1;
    fprintf(OUTPUT, "\nError, sending key request failed [%s].", __FUNCTION__);
  }

  p_enc_dev_keys = (sp_aes_gcm_data_t*)((uint8_t*)key_resp + sizeof(kd_samp_package_header_t));

  ret = ecall_put_keys(global_eid, &status, p_enc_dev_keys->payload, p_enc_dev_keys->payload_size, p_enc_dev_keys->payload_tag);
  if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)){
    fprintf(OUTPUT, "\nError, encrypted key set secret using secret_share_key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
    goto FINAL;
  }

  fprintf(OUTPUT, "\nDevice keys loaded in the enclave.\n");

  fprintf(OUTPUT, "\n\n***Starting Data Request Functionality***\n");

  fprintf(OUTPUT, "\nRequest data from the cloud storage.\n");

  fprintf(OUTPUT, "\nDev0_0\n");
  ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 0, &dev_0_offset_0_data_resp);

  if(ret !=0 || !dev_0_offset_0_data_resp){
    ret = -1;
    fprintf(OUTPUT, "\nError, dev 0 offset 0 data retrieve failed [%s].", __FUNCTION__);
  }

  fprintf(OUTPUT, "\nDev0_1\n");
  p_enc_dev_0_offset_0_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_0_data_resp + sizeof(du_samp_package_header_t));

  ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 1, &dev_0_offset_1_data_resp);

  if(ret !=0 || !dev_0_offset_1_data_resp){
    ret = -1;
    fprintf(OUTPUT, "\nError, dev 0 offset 1 data retrieve failed [%s].", __FUNCTION__);
  }

  fprintf(OUTPUT, "\nDev0_2\n");
  p_enc_dev_0_offset_1_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_1_data_resp + sizeof(du_samp_package_header_t));

  ret = dr_network_send_receive("http://demo_testing.storage.cloud/", 0, 2, &dev_0_offset_2_data_resp);

  if(ret !=0 || !dev_0_offset_2_data_resp){
    ret = -1;
    fprintf(OUTPUT, "\nError, dev 0 offset 2 data retrieve failed [%s].", __FUNCTION__);
  }

  p_enc_dev_0_offset_2_data = (sp_aes_gcm_data_t*)((uint8_t*)dev_0_offset_2_data_resp + sizeof(du_samp_package_header_t));

  printf("\n***Perform Statistics Function Over Dev0_0, Dev0_1***\n\n");

  ret = ecall_perform_statistics(global_eid, &status, p_enc_dev_0_offset_0_data->payload, p_enc_dev_0_offset_0_data->payload_size, p_enc_dev_0_offset_0_data->payload_tag, 0,  p_enc_dev_0_offset_1_data->payload, p_enc_dev_0_offset_1_data->payload_size, p_enc_dev_0_offset_1_data->payload_tag, 0, &perform_sum_fun_result);


  printf("\nthe final sum value returned from the enclave is: %d\n\n", perform_sum_fun_result);

  /*
    start heartbeat mechanism for the enclave, or no ecall function can be executed
  */

  printf("\n\n***Starting Heartbeat Functionality***\n");
  // ecall_start_heartbeat(global_eid, &status);

  pthread_create(&hb_id, NULL, heartbeat_event_loop, (void *)&hb_freq);

  for(int c=1; c <= 15; c++){
    printf("\n\nMain thread: %d\n", c);

    printf("\n***Perform Statistics Function Over Dev0_0, Dev0_1***\n\n");

    ret = ecall_perform_statistics(global_eid, &status, p_enc_dev_0_offset_0_data->payload, p_enc_dev_0_offset_0_data->payload_size, p_enc_dev_0_offset_0_data->payload_tag, 0,  p_enc_dev_0_offset_1_data->payload, p_enc_dev_0_offset_1_data->payload_size, p_enc_dev_0_offset_1_data->payload_tag, 0, &perform_sum_fun_result);


    printf("\nthe final sum value returned from the enclave is: %d\n\n", perform_sum_fun_result);

    sleep(3);
  }

FINAL:

  /*
    when an encalve is stoped, you need end hearbeat mechanism exploitly by revoking ecall_end_heartbeat()
  */
  // ecall_end_heartbeat(global_eid, &status);

  sgx_destroy_enclave(global_eid);

  printf("\n\nInfo: Enclave Successfully Retrurned. \n");

  printf("Enter a character before exit ... \n");
  getchar();
  pthread_exit(NULL);
  return ret;
}
