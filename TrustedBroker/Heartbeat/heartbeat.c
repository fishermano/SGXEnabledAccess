#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "heartbeat.h"

#include "remote_attestation_result.h" // for encrypted data format sp_aes_gcm_data_t

#include "sample_libcrypto.h"

#include "key_management.h"

#define SAMPLE_SP_IV_SIZE 12
#define REVOKED_THRESHOLD 10

extern sp_samp_ssk_t hcp_0;

static uint8_t ct = 1;

uint8_t counter(){
  return ct++;
}

int sp_heart_beat_loop(hb_samp_package_header_t **response){

  hb_samp_package_header_t *p_resp = NULL;
  sp_aes_gcm_data_t *p_encrypted_data = NULL;
  sp_samp_heartbeat_data_t *p_heartbeat_data = NULL;

  p_heartbeat_data = (sp_samp_heartbeat_data_t *)malloc(sizeof(sp_samp_heartbeat_data_t));
  if(NULL == p_heartbeat_data){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }

  p_heartbeat_data->counter = counter();
  p_heartbeat_data->is_revoked = 0;
  if(p_heartbeat_data->counter >= REVOKED_THRESHOLD){
    p_heartbeat_data->is_revoked = 1;
  }

  fprintf(stdout, "\ncurrent sending heartbeat counter: %d \n", p_heartbeat_data->counter);

  uint32_t heartbeat_data_size = sizeof(sp_samp_heartbeat_data_t);

  uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};

  p_encrypted_data = (sp_aes_gcm_data_t *)malloc(sizeof(sp_aes_gcm_data_t) + heartbeat_data_size);
  memset(p_encrypted_data, 0, sizeof(sp_aes_gcm_data_t) + heartbeat_data_size);
  if(!p_encrypted_data){
    fprintf(stderr, "\nError, out of memory in [%s].\n", __FUNCTION__);
    return -1;
  }

  int ret = sample_rijndael128GCM_encrypt(&hcp_0.key,
              &p_heartbeat_data->counter,
              heartbeat_data_size,
              p_encrypted_data->payload,
              &aes_gcm_iv[0],
              SAMPLE_SP_IV_SIZE,
              NULL,
              0,
              &p_encrypted_data->payload_tag);

  p_encrypted_data->payload_size = heartbeat_data_size;

  p_resp = (hb_samp_package_header_t *)malloc(sizeof(hb_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + heartbeat_data_size);
  if(!p_resp){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(p_resp, 0, sizeof(hb_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + heartbeat_data_size);

  p_resp->size = sizeof(sp_aes_gcm_data_t) + heartbeat_data_size;

  memcpy(p_resp->body, p_encrypted_data, sizeof(sp_aes_gcm_data_t) + heartbeat_data_size);

  *response = p_resp;

  return 0;
}
