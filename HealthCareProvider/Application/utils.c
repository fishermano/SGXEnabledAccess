#include "sgx_ukey_exchange.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "remote_attestation_result.h"

#include "ThirdPartyLibrary/remote_attestation.h"
#include "ThirdPartyLibrary/key_management.h"
#include "ThirdPartyLibrary/data_upload.h"
#include "ThirdPartyLibrary/heartbeat.h"

#define LEN_OF_PACKAGE_HEADER 8
#define BUFFER_SIZE 4096
#define DEFAULT_PORT 8000

// Some utility functions to output some of the data structures passed between
// the app and the trusted broker.
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len){
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, pkg_header_t *response){
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->reserved[0],
            response->reserved[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

/* Used to send requests to the service provider sample.  It simulates network communication between the demo_app and the trusted broker.  This would be modified in a real product to use the proper IP communication.

 * @param server_url String name of the server URL
 * @param p_req Pointer to the message to be sent.
 * @param p_resp Pointer to a pointer of the response message.

 * @return int
*/

int ra_network_send_receive(const char *server_url, const pkg_header_t *p_req, pkg_header_t **p_resp){
  int ret = 0;
  pkg_header_t *p_resp_msg;

  if((NULL == server_url) || (NULL == p_req) || (NULL == p_resp)){
    ret = -1;
    return ret;
  }

  switch (p_req->type) {
    case TYPE_RA_MSG0:
      ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((uint8_t*)p_req
          + sizeof(pkg_header_t)),
          p_req->size);
      if (0 != ret)
      {
          fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
              __FUNCTION__);
      }
      break;
    case TYPE_RA_MSG1:
      ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)p_req
          + sizeof(pkg_header_t)),
          p_req->size,
          &p_resp_msg);
      if(0 != ret)
      {
          fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
              __FUNCTION__);
      }
      else
      {
          *p_resp = p_resp_msg;
      }
      break;
    case TYPE_RA_MSG3:
      ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((uint8_t*)p_req +
          sizeof(pkg_header_t)),
          p_req->size,
          &p_resp_msg);
      if(0 != ret)
      {
          fprintf(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].",
              __FUNCTION__);
      }
      else
      {
          *p_resp = p_resp_msg;
      }
      break;
    default:
      ret = -1;
      fprintf(stderr, "\nError, unknown remote attestation message type. Type = %d [%s].", p_req->type, __FUNCTION__);
      break;
  }

  return ret;
}

int kq_network_send_receive(const char *server_url, const pkg_header_t *p_req, pkg_header_t **p_resp){
  int ret = 0;

  int socket_fd;
  struct sockaddr_in servaddr;

  if( (socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
    printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(server_url);
  servaddr.sin_port = htons(DEFAULT_PORT);

  if( connect(socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0 ){
    printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  printf("+++++++hcp sending key request+++++++\n");

  char *req_data_buf;
  pkg_serial(p_req, &req_data_buf);

  int n = 0;
  n = send(socket_fd, req_data_buf, PKG_SIZE, 0);
  if( n <= 0){
    printf("hcp send request data error: %s(errno: %d)", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  printf("+++++++hcp receiving response from hcp+++++++\n");

  char *res_data_buf = (char *)malloc(PKG_SIZE);
  n = recv(socket_fd, res_data_buf, PKG_SIZE, 0);
  if( n < 0 ){
    printf("hcp receive data error: %s(errno: %d)", strerror(errno), errno);
    ret = -1;
    return ret;
  }

  pkg_header_t *res_tmp;
  pkg_deserial(res_data_buf, &res_tmp);

  *p_resp = res_tmp;

  free(req_data_buf);
  free(res_data_buf);
  return ret;
}

int dr_network_send_receive(const char *server_url, const uint8_t dev_id, const uint8_t offset, pkg_header_t **p_resp){
  int ret = 0;
  pkg_header_t *p_resp_msg;

  if(NULL == server_url){
    ret = -1;
    return ret;
  }

  ret = sp_upload_data(server_url, dev_id, offset, &p_resp_msg);

  if(0 != ret)
  {
      fprintf(stderr, "\nError, call sp_upload_data fail [%s].",
          __FUNCTION__);
  }
  else
  {
      *p_resp = p_resp_msg;
  }

  return ret;
}

int hb_network_send_receive(const char *server_url, pkg_header_t **p_resp){

  int ret = 0;
  pkg_header_t *p_resp_msg;

  if(NULL == server_url){
    ret = -1;
    return ret;
  }

  ret = sp_heart_beat_loop(&p_resp_msg);

  if(0 != ret)
  {
      fprintf(stderr, "\nError, call sp_heart_beat_loop fail [%s].",
          __FUNCTION__);
  }
  else
  {
      *p_resp = p_resp_msg;
  }

  return ret;
}

void write_result(const char *res_file, int file_num, double dec_time){
  FILE *out = fopen(res_file, "a");
  if (out == NULL){
    printf("cannot open file %s\n", res_file);
    return;
  }
  fprintf(out, "%d,%lf\n", file_num, dec_time);
  fclose(out);
  return;
}
