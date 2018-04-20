#include "sgx_tcrypto.h"
#include "string.h"
#include <time.h>

#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

extern key_set_t *device_keys;

sgx_status_t ecall_perform_statistics(uint8_t* p_secret_1, uint32_t secret_size_1, uint8_t* gcm_mac_1, uint8_t dev_id_1,  uint8_t* p_secret_2, uint32_t secret_size_2, uint8_t* gcm_mac_2, uint8_t dev_id_2, uint32_t *result){
  myprintf("testing enclave function: ecall_perform_statistics()\n");

  if( 0 == hb_assert() ){
      myprintf("!!!Heartbeat mechanism force the enclave not available!!!\n");

      return SGX_ERROR_UNEXPECTED;
  }

  float mean = 0.0;
  float variance = 0.0;

  if(NULL == device_keys){
    myprintf("current key set is null, keys can be requested or uncovered from second storage\n");

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

    ret = sgx_rijndael128GCM_decrypt(&secret_key_2, p_secret_2, secret_size_2, &data_2->size, &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(gcm_mac_2));

    uint32_t i;


    for(i=0;i<data_1->size;i++){
        *result = *result + data_1->data[i];
    }

    for(i=0;i<data_2->size;i++){
        *result = *result + data_2->data[i];
    }

    mean = (*result / 16);

    for(i=0;i<data_1->size;i++){
        variance = variance + ((data_1->data[i] - mean) * (data_1->data[i] - mean)) / (16 - 1);
    }

    for(i=0;i<data_2->size;i++){
        variance = variance + ((data_2->data[i] - mean) * (data_2->data[i] - mean)) / (16 - 1);
    }

    myprintf("\nThe mean value: %lf\n", mean);
    myprintf("\nThe variance value: %lf\n", variance);

    // Once the server has the shared secret, it should be sealed to
    // persistent storage for future use. This will prevents having to
    // perform remote attestation until the secret goes stale. Once the
    // enclave is created again, the secret can be unsealed.

  }while(0);

  return ret;
}
