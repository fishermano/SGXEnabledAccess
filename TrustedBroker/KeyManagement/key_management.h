#ifndef _KEY_MANAGEMENT_H
#define _KEY_MANAGEMENT_H

#include "key_delivery.h"
#include "sample_libcrypto.h"

typedef struct sp_samp_dev_key_t{
  uint8_t dev_id;
  sample_aes_gcm_128bit_key_t key;
}sp_samp_dev_key_t;

typedef struct sp_samp_ssk_t{
  uint8_t hcp_id;
  sample_aes_gcm_128bit_key_t key;
}sp_samp_ssk_t;

typedef struct hcp_samp_certificate_t{
  uint8_t id;
  sample_ec256_signature_t sig;
}hcp_samp_certificate_t;

typedef struct sp_samp_key_set_t{
  uint8_t key_num;
  sample_aes_gcm_128bit_key_t keys[];
}sp_samp_key_set_t;

int key_generate(uint8_t dev_id);

int key_access(uint8_t hcp_id, sp_samp_key_set_t **pp_key_set);

int sp_km_proc_key_req(const hcp_samp_certificate_t *request, kd_samp_package_header_t **response);

#endif
