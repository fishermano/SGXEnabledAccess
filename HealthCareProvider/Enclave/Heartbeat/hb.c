#include "sgx_tae_service.h"
#include <string.h>

#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

extern sgx_time_t hb_state;
extern sgx_time_source_nonce_t nonce;
extern uint8_t r_max;
extern uint8_t u_shared_key[16];
extern uint8_t shared_key[16];


void erase(){

}

/*
 * SUCCESS: 1
 * REVOKED: 2
 * REPLAY: 3
 *
 */

sgx_status_t ecall_heartbeat_process(uint8_t* p_hb, uint32_t hb_size, uint8_t* gcm_hb_mac, uint32_t *res_status){
  ocall_print("testing enclave function: ecall_heartbeat_process()");

  uint8_t base[16] = {0};
  if(memcmp(base, u_shared_key, sizeof(u_shared_key)) == 0){
    memcpy(u_shared_key, shared_key, sizeof(shared_key));
  }

  sgx_status_t ret = SGX_SUCCESS;

  heartbeat_data_t *hb = (heartbeat_data_t *)malloc(sizeof(heartbeat_data_t));

  uint8_t aes_gcm_iv[12] = {0};
  ret = sgx_rijndael128GCM_decrypt(&u_shared_key, p_hb, hb_size, &hb->r, &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(gcm_hb_mac));

  ocall_print("decrypted current counter:");
  ocall_print_int(hb->r);
  ocall_print("decrypted is_revoked:");
  ocall_print_int(hb->is_revoked);

  ocall_print("maximum counter received before:");
  ocall_print_int(r_max);

  if( r_max < hb->r ){

    r_max = hb->r;

    if( 1 == hb->is_revoked ){
      ocall_print("REVOKED\n");
      *res_status = 2;
      erase();
    }else if( 0 == hb->is_revoked){
      ocall_print("SUCCESS");
      ret = sgx_create_pse_session();
      if(SGX_SUCCESS != ret){
        return ret;
      }

      ret = sgx_get_trusted_time(&hb_state, &nonce);
      if(SGX_SUCCESS != ret)
      {
        return ret;
      }

      ocall_print("current state:");
      ocall_print_int((int) hb_state);
      sgx_close_pse_session();
      *res_status = 1;
    }

  }else{
    ocall_print("REPLAY\n");
    *res_status = 3;
  }

  return ret;
}
