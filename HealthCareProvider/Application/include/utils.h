#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

// Needed for definition of network package.
#include "network.h"

/*
  for printing some data in memory
*/
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, pkg_header_t *response);

/*
  interface for communication between demp_app and trusted borker
*/
int ra_network_send_receive(const char *server_url, const pkg_header_t *p_req, pkg_header_t **p_resp);

int kq_network_send_receive(const char *server_url, const pkg_header_t *p_req, pkg_header_t **p_resp);

int dr_network_send_receive(const char *server_url, const uint8_t dev_id, const uint8_t offset, pkg_header_t **p_resp);

int hb_network_send_receive(const char *server_url, pkg_header_t **p_resp);

void write_result(const char *res_file, int file_num, double dec_time);

#endif
