
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "network.h"

void pkg_serial(const pkg_header_t *pkg_header, char ** pkg){

  pkg_t *pkg_tmp = (pkg_t *)malloc(PKG_SIZE);
  pkg_tmp->type = pkg_header->type;
  pkg_tmp->size = pkg_header->size;
  memcpy(pkg_tmp->reserved, pkg_header->reserved, 3);
  memcpy(pkg_tmp->body, pkg_header->body, pkg_header->size);

  char *tmp = (char *)malloc(PKG_SIZE);
  memcpy(tmp, pkg_tmp, PKG_SIZE);

  free(pkg_tmp);
  *pkg = tmp;

}

void pkg_deserial(const char *pkg, pkg_header_t ** pkg_header){

  pkg_t *pkg_tmp = (pkg_t *)malloc(PKG_SIZE);
  memcpy(pkg_tmp, pkg, PKG_SIZE);

  pkg_header_t *pkg_header_tmp = (pkg_header_t *)malloc(sizeof(pkg_header_t) + pkg_tmp->size);
  pkg_header_tmp->type = pkg_tmp->type;
  pkg_header_tmp->size = pkg_tmp->size;
  memcpy(pkg_header_tmp->reserved, pkg_tmp->reserved, 3);
  memcpy(pkg_header_tmp->body, pkg_tmp->body, pkg_tmp->size);

  free(pkg_tmp);
  *pkg_header = pkg_header_tmp;
}
