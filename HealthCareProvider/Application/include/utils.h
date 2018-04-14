#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

// Needed for definition of remote attestation messages.
#include "network_ra.h"
#include "key_delivery.h"
#include "data_delivery.h"
#include "hb_delivery.h"

/*
  for printing some data in memory
*/
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, ra_samp_response_header_t *response);

/*
  interface for communication between demp_app and trusted borker
*/
int ra_network_send_receive(const char *server_url, const ra_samp_request_header_t *p_req, ra_samp_response_header_t **p_resp);

int kq_network_send_receive(const char *server_url, const kd_samp_package_header_t *p_req, kd_samp_package_header_t **p_resp);

int dr_network_send_receive(const char *server_url, const uint8_t dev_id, const uint8_t offset, du_samp_package_header_t **p_resp);

int hb_network_send_receive(const char *server_url, hb_samp_package_header_t **p_resp);

void write_result(const char *res_file, int file_num, double dec_time);

#endif
