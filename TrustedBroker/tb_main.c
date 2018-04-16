#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
  int n;

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

  printf("=======waiting for hcp's request=======\n");
  while(1){
    if( (connect_fd = accept(socket_fd, (struct sockaddr*)NULL, NULL)) == -1 ){
      printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
      continue;
    }

    header *pkg_header = (header *)malloc(sizeof(header));
    char *pkg_header_buf = (char *)malloc(LEN_OF_PACKAGE_HEADER);
    //receive package header from hcp
    n = recv(connect_fd, pkg_header_buf, LEN_OF_PACKAGE_HEADER, 0);
    if( n < 0 ){
      printf("server receive data failed!\n");
      break;
    }
    memcpy(pkg_header, pkg_header_buf, LEN_OF_PACKAGE_HEADER);

    uint32_t data_size = pkg_header->size;
    pkg_header_t *pkg = (pkg_header_t *)malloc(sizeof(pkg_header_t) + data_size);
    memcpy(pkg, pkg_header, LEN_OF_PACKAGE_HEADER);

    char *data_buf = (char *)malloc(data_size);

    int pos = 0;
    while(pos < data_size){
      n = recv(connect_fd, data_buf+pos, BUFFER_SIZE, 0);
      if( n < 0 ){
        printf("server receive data failed!\n");
        break;
      }
      pos += n;
    }
    memcpy(pkg+LEN_OF_PACKAGE_HEADER, data_buf, data_size);


    //send back reponse data to client
    if( !fork() ){
      if( send(connect_fd, "hello, you are connected!\n", 26, 0) == -1){
        perror("send error");
      }

      close(connect_fd);

    }

    free(data_buf);
    free(pkg_header_buf);
    //close(connect_fd);
  }

  close(socket_fd);

  return 0;

}
