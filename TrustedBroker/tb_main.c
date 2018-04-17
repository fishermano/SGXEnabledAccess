#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "key_management.h"

#include "network.h"

#define LEN_OF_PACKAGE_HEADER 8
#define LEN_OF_LISTEN_QUENE 20
#define DEFAULT_PORT 8000
#define BUFFER_SIZE 4096

typedef struct{
  uint8_t type;
  uint32_t size;
  uint8_t reserved[3];
}header;

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
    printf("=======waiting for hcp's request=======\n");
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

    pkg_header_t *pkg;
    pkg_deserial(req_data_buf, &pkg);

    int ret = 0;
    switch( pkg->type ){
      case TYPE_RA_MSG0:

        break;
      case TYPE_RA_MSG1:

        break;
      case TYPE_RA_MSG3:

        break;
      case TYPE_KEY_REQ:
        pkg_header_t *p_resp_msg;
        ret = sp_km_proc_key_req((const hcp_samp_certificate_t*)((uint8_t*)pkg
            + sizeof(pkg_header_t)), &p_resp_msg);
        if(0 != ret)
        {
            printf("call sp_km_proc_key_req fail error: %s(errno: %d)", strerror(errno), errno);
        }

        if( !fork() ){

          printf("+++++++trusted broker sending response to hcp+++++++\n");

          char *res_data_buf;
          pkg_serial(p_resp_msg, &res_data_buf);

          n = send(connect_fd, res_data_buf, PKG_SIZE, 0);
          if( n <= 0){
            printf("trusted broker send response data error: %s(errno: %d)", strerror(errno), errno);
            break;
          }

        }

        break;
      default:
        printf("unknown package type error: %s(errno: %d)", strerror(errno), errno);
        break;
    }

    close(connect_fd);
  }

  close(socket_fd);

  return 0;

}
