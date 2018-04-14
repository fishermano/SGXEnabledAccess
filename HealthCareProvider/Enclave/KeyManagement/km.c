#include "sgx_tcrypto.h"
#include "string.h"

#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

extern uint8_t u_shared_key[16];
extern key_set_t *device_keys;
extern uint8_t hb_state;

sgx_status_t ecall_put_keys(uint8_t *p_secret, uint32_t secret_size, uint8_t *p_gcm_mac){
  ocall_print("\ntesting enclave function: ecall_put_keys()");

  // if(STATUS_HB_ACTIVE != hb_state){
  //   ocall_print("\nHeartbeat mechanism is not active, please make sure to active it by revoking ecall_start_heartbeat()\n");
  //
  //   return SGX_ERROR_UNEXPECTED;
  // }

  if(NULL == device_keys){
    ocall_print("\ncurrent key set is null\n");
    device_keys = (key_set_t *)malloc(sizeof(key_set_t));
    if(NULL == device_keys){
      ocall_print("Error, out of memory in ecall_put_keys()");
      return SGX_ERROR_UNEXPECTED;
    }
    memset(device_keys, 0, sizeof(key_set_t));
  }

  sgx_status_t ret = SGX_SUCCESS;

  do{

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(&u_shared_key, p_secret, secret_size, &device_keys->key_num, &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(p_gcm_mac));

    // uint32_t i;
    // bool secret_match = true;
    // for(i=0;i<secret_size;i++){
    //     if(secret_share_key[i] != i){
    //       secret_match = false;
    //     }
    // }
    //
    // if(!secret_match){
    //   ret = SGX_ERROR_UNEXPECTED;
    // }

    // Once the server has the shared secret, it should be sealed to
    // persistent storage for future use. This will prevents having to
    // perform remote attestation until the secret goes stale. Once the
    // enclave is created again, the secret can be unsealed.
    ocall_print("decrypted key number:");
    ocall_print_int(device_keys->key_num);

    // uint32_t i,j;
    // for(i=0;i<device_keys->key_num;i++){
    //   for(j=0;j<16;j++){
    //     ocall_print_int(device_keys->device_keys[i][j]);
    //   }
    //   ocall_print("\n##################################\n");
    // }

  }while(0);

  return ret;
}
