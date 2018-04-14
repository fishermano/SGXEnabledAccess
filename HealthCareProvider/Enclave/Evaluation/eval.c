
#include "sgx_tcrypto.h"
#include "string.h"

#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

//#include "mycrypto.h"

extern uint8_t shared_key[16];

struct file_t {
    uint8_t payload_size;
    uint8_t offset[7];
    uint8_t payload_tag[16];
    uint8_t payload[8];
};

sgx_status_t ecall_evaluate_decryption(uint8_t *p_files, uint32_t file_number, uint32_t total_size){

  ocall_print("testing enclave function: ecall_evaluate_decryption()");
  ocall_print_int(file_number);
  ocall_print_int(total_size);

  sgx_status_t ret = SGX_SUCCESS;

  uint8_t data[8] = {0};
  uint8_t aes_gcm_iv[12] = {0};

  struct file_t *file = (struct file_t *)malloc(32);

  for(uint32_t i = 0; i < file_number; i++){
    memcpy(file, p_files, 32);

    ret = sgx_rijndael128GCM_decrypt(&shared_key, file->payload, file->payload_size, &data[0], &aes_gcm_iv[0], 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *)(file->payload_tag));
    p_files = p_files + 32;
  }

  return ret;
}
