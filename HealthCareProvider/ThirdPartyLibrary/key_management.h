#ifndef _KEY_MANAGEMENT_H
#define _KEY_MANAGEMENT_H

#include "key_delivery.h"
#include "sample_libcrypto.h"

typedef struct hcp_samp_certificate_t{
  uint8_t id;
  sample_ec256_signature_t sig;
}hcp_samp_certificate_t;

typedef struct sp_samp_key_set_t{
  uint8_t key_num;
  sample_aes_gcm_128bit_key_t keys[];
}sp_samp_key_set_t;

int sp_km_proc_key_req(const hcp_samp_certificate_t *request, kd_samp_package_header_t **response);

#endif
