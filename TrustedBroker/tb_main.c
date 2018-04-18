#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "key_management.h"
#include "remote_attestation.h"

#include "network.h"

#define LEN_OF_PACKAGE_HEADER 8
#define LEN_OF_LISTEN_QUENE 20
#define DEFAULT_PORT 8001
#define BUFFER_SIZE 4096

// This is a context data structure used on SP side

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

int main(int argc, char** argv){

  int socket_fd, connect_fd;
  struct sockaddr_in servaddr;

  //initialize socket
  if( (socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
    printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
    exit(0);
  }

  //initialize socket address
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY); //set ip address as host ip address
  servaddr.sin_port = htons(DEFAULT_PORT); //set port as default port

  //bind the socket address to the socket
  if( bind(socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1 ){
    printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
    exit(0);
  }

  //listen whether there are clients connecting
  if( listen(socket_fd, LEN_OF_LISTEN_QUENE) == -1){
    printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
    exit(0);
  }

  while(1){
    printf("\n\n=======waiting for hcp's request=======\n");
    if( (connect_fd = accept(socket_fd, (struct sockaddr*)NULL, NULL)) == -1 ){
      printf("trusted broker accept socket error: %s(errno: %d)", strerror(errno), errno);
      continue;
    }

    //receive package header from hcp

    printf("+++++++trusted broker receiving request from hcp+++++++\n");

    char *req_data_buf = (char *)malloc(PKG_SIZE);
    int n = recv(connect_fd, req_data_buf, PKG_SIZE, 0);
    if( n < 0 ){
      printf("trusted broker receive data error: %s(errno: %d)", strerror(errno), errno);
      exit(0);
    }

    pkg_header_t *req_pkg = NULL;
    pkg_deserial(req_data_buf, &req_pkg);

    int ret = 0;
    char *res_data_buf = NULL;
    pkg_header_t *res_pkg = NULL;
    switch( req_pkg->type ){
      case TYPE_RA_MSG0:
        printf("*******trusted broker receiving TYPE_RA_MSG0: *******\n");
        PRINT_BYTE_ARRAY(stdout, req_pkg->body, req_pkg->size);
        ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((uint8_t*)req_pkg
            + sizeof(pkg_header_t)),
            req_pkg->size);
        if (0 != ret)
        {
          printf("call sp_ra_proc_msg0_req error: %s(errno: %d)", strerror(errno), errno);
          break;
        }
        break;
      case TYPE_RA_MSG1:
        printf("*******trusted broker receiving TYPE_RA_MSG1: *******\n");
        PRINT_BYTE_ARRAY(stdout, req_pkg->body, req_pkg->size);
        ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)req_pkg + sizeof(pkg_header_t)), req_pkg->size, &res_pkg);
        if(0 != ret)
        {
          printf("call sp_ra_proc_msg1_req error: %s(errno: %d)", strerror(errno), errno);
          break;
        }
        if( !fork() ){

          printf("-------trusted broker sending back TYPE_RA_MSG2: -------\n");
          PRINT_BYTE_ARRAY(stdout, res_pkg->body, res_pkg->size);
          pkg_serial(res_pkg, &res_data_buf);

          n = send(connect_fd, res_data_buf, PKG_SIZE, 0);
          if( n <= 0){
            printf("trusted broker send back TYPE_RA_MSG2 error: %s(errno: %d)", strerror(errno), errno);
            break;
          }
        }
        break;
      case TYPE_RA_MSG3:
        printf("*******trusted broker receiving TYPE_RA_MSG3: *******\n");
        PRINT_BYTE_ARRAY(stdout, req_pkg->body, req_pkg->size);

        ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t *)((uint8_t*)req_pkg + sizeof(pkg_header_t)), req_pkg->size, &res_pkg);
        if(0 != ret)
        {
          printf("call sp_ra_proc_msg3_req error: %s(errno: %d)", strerror(errno), errno);
          break;
        }
        if( !fork() ){

          printf("------trusted broker sending back TYPE_RA_ATT_RESULT (MSG4): -------\n");
          PRINT_BYTE_ARRAY(stdout, res_pkg->body, res_pkg->size);
          pkg_serial(res_pkg, &res_data_buf);

          n = send(connect_fd, res_data_buf, PKG_SIZE, 0);
          if( n <= 0){
            printf("trusted broker send back TYPE_RA_ATT_RESULT (MSG4) error: %s(errno: %d)", strerror(errno), errno);
            break;
          }
        }
        break;
      case TYPE_KEY_REQ:
        printf("*******trusted broker receiving TYPE_KEY_REQ: *******\n");
        PRINT_BYTE_ARRAY(stdout, req_pkg->body, req_pkg->size);
        ret = sp_km_proc_key_req((const hcp_samp_certificate_t*)((uint8_t*)req_pkg + sizeof(pkg_header_t)), &res_pkg);
        if(0 != ret)
        {
          printf("call sp_km_proc_key_req error: %s(errno: %d)", strerror(errno), errno);
          break;
        }

        if( !fork() ){

          printf("-------trusted broker sending back TYPE_KEY_RES: -------\n");
          PRINT_BYTE_ARRAY(stdout, res_pkg->body, res_pkg->size);
          pkg_serial(res_pkg, &res_data_buf);

          n = send(connect_fd, res_data_buf, PKG_SIZE, 0);
          if( n <= 0){
            printf("trusted broker send back TYPE_KEY_RES error: %s(errno: %d)", strerror(errno), errno);
            break;
          }
        }
        break;
      default:
        printf("unknown package type error: %s(errno: %d)", strerror(errno), errno);
        break;
    }

    free(req_data_buf);
    if(NULL != res_data_buf){
      free(res_data_buf);
    }
    if(NULL != res_pkg){
      free(res_pkg);
    }
    if(NULL != req_pkg){
      free(req_pkg);
    }
    close(connect_fd);
  }

  close(socket_fd);

  return 0;

}
