/*
  this file defines enclave global parameters
*/

#include <stdint.h>
#include "string.h"

#include "sgx_tae_service.h"

#include "demo_enclave.h"

//heartbeat mechanism status
sgx_time_t cur_time = -1;
sgx_time_t hb_state = -1;
sgx_time_source_nonce_t nonce = {0};
int threshold = 4;

// secret shared key between demo_app and trusted broker
// during remote attestation
uint8_t shared_key[16] = {0};
// uncovered
uint8_t u_shared_key[16] = {0};

// device keys received from trusted broker
key_set_t *device_keys = NULL;

// maximum counter of received heartbeat
uint8_t r_max = 0;

uint8_t assert(void){
  sgx_status_t ret = SGX_SUCCESS;
  ret = sgx_create_pse_session();
  if(SGX_SUCCESS != ret){
    return 0;
  }
  ret = sgx_get_trusted_time(&cur_time, &nonce);
  if(SGX_SUCCESS != ret)
  {
    sgx_close_pse_session();
    return 0;
  }
  if(-1 == hb_state){
    sgx_close_pse_session();
    return 0;
  }

  int diff_time = (int)cur_time - (int)hb_state;
  if(diff_time <= threshold){
    sgx_close_pse_session();
    return 1;
  }

  sgx_close_pse_session();
  return 0;
}
