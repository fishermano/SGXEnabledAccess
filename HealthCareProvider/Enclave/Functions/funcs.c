#include "sgx_tcrypto.h"
#include "string.h"
#include <time.h>

#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

extern key_set_t *device_keys;
extern uint8_t assert(void);

sgx_status_t ecall_perform_statistics(uint8_t* p_secret_1, uint32_t secret_size_1, uint8_t* gcm_mac_1, uint8_t dev_id_1,  uint8_t* p_secret_2, uint32_t secret_size_2, uint8_t* gcm_mac_2, uint8_t dev_id_2, uint32_t *result){
  ocall_print("testing enclave function: ecall_perform_statistics()");

  // if(STATUS_HB_ACTIVE != hb_state){
  //   ocall_print("\nHeartbeat mechanism is not active, please make sure to active it by revoking ecall_start_heartbeat()\n");
  //
  //   return SGX_ERROR_UNEXPECTED;
  // }
  if( 0 == assert() ){
      ocall_print("\n!!!Heartbeat mechanism force the enclave not available!!!\n");

      return SGX_ERROR_UNEXPECTED;
  }

  float mean = 0.0;
  float variance = 0.0;

  if(NULL == device_keys){
    ocall_print("\ncurrent key set is null, keys can be requested or uncovered from second storage\n");

    return SGX_ERROR_SERVICE_UNAVAILABLE;
  }

  sgx_status_t ret = SGX_SUCCESS;

  uint8_t secret_key_1[16] = {0};
  uint8_t secret_key_2[16] = {0};

  switch (dev_id_1){
    case 0:
      memcpy(&secret_key_1[0], device_keys->device_keys[0], 16);
      break;
    case 1:
      memcpy(&secret_key_1[1], device_keys->device_keys[1], 16);
      break;
    case 2:
      memcpy(&secret_key_1[2], device_keys->device_keys[2], 16);
      break;
    case 3:
      memcpy(&secret_key_1[3], device_keys->device_keys[3], 16);
      break;
  }

  switch (dev_id_2){
    case 0:
      memcpy(&secret_key_2[0], device_keys->device_keys[0], 16);
      break;
    case 1:
      memcpy(&secret_key_2[1], device_keys->device_keys[1], 16);
      break;
    case 2:
      memcpy(&secret_key_2[2], device_keys->device_keys[2], 16);
      break;
    case 3:
      memcpy(&secret_key_2[3], device_keys->device_keys[3], 16);
      break;
  }

  *result = 0;

  do{

    dev_data_t *data_1 = (dev_data_t *)malloc(sizeof(dev_data_t));
    dev_data_t *data_2 = (dev_data_t *)malloc(sizeof(dev_data_t));

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(&secret_key_1, p_secret_1, secret_size_1, &data_1->size, &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(gcm_mac_1));

    // ocall_print("\nDecrypted secret data 1 size:\n");
    // ocall_print_int(data_1->size);
    // ocall_print("\n");
    // ocall_print("\n##################################\n");

    ret = sgx_rijndael128GCM_decrypt(&secret_key_2, p_secret_2, secret_size_2, &data_2->size, &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(gcm_mac_2));

    // ocall_print("\nDecrypted secret data 2 size:\n");
    // ocall_print_int(data_2->size);
    // ocall_print("\n");

    uint32_t i;


    for(i=0;i<data_1->size;i++){
        // ocall_print_int(data_1->data[i]);
        *result = *result + data_1->data[i];
    }

    for(i=0;i<data_2->size;i++){
        // ocall_print_int(data_2->data[i]);
        *result = *result + data_2->data[i];
    }
    // ocall_print("\n##################################\n");

    mean = (*result / 16);

    for(i=0;i<data_1->size;i++){
        variance = variance + ((data_1->data[i] - mean) * (data_1->data[i] - mean)) / (16 - 1);
    }

    for(i=0;i<data_2->size;i++){
        variance = variance + ((data_2->data[i] - mean) * (data_2->data[i] - mean)) / (16 - 1);
    }

    ocall_print("\nThe mean value:");
    ocall_print_int((int)mean);
    ocall_print("\nThe variance value:");
    ocall_print_int((int)variance);

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

  }while(0);

  return ret;
}
