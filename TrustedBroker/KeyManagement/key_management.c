#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "key_management.h"
#include "remote_attestation_result.h"
#include "policy_management.h"

#define SAMPLE_SP_IV_SIZE        12

// extern sample_aes_gcm_128bit_key_t secret_share_key;
// extern sample_aes_gcm_128bit_key_t d_key1;
// extern sample_aes_gcm_128bit_key_t d_key2;
// extern sample_aes_gcm_128bit_key_t d_key3;
// extern sample_aes_gcm_128bit_key_t d_key4;
extern sp_samp_ssk_t hcp_0;

extern sp_samp_dev_key_t dev_0;
extern sp_samp_dev_key_t dev_1;
extern sp_samp_dev_key_t dev_2;
extern sp_samp_dev_key_t dev_3;


int request_check(){
  return 0;
}

int key_access(uint8_t hcp_id, sp_samp_key_set_t **pp_key_set){

  sp_samp_access_rule_t *p_access_rule = NULL;

  if(0 != policy_access(hcp_id, &p_access_rule)){
    return -1;
  }


  sp_samp_key_set_t *key_set = NULL;
  uint8_t key_num = p_access_rule->dev_num;

  uint32_t key_size = key_num * sizeof(sample_aes_gcm_128bit_key_t);
  key_set = (sp_samp_key_set_t *)malloc(sizeof(sp_samp_key_set_t) + key_size);
  if(NULL == key_set){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(key_set, 0, sizeof(sp_samp_key_set_t) + key_size);

  key_set->key_num = key_num;
  for(uint8_t r =0; r < key_num; r++){
    if(0 == p_access_rule->dev_list[r]){
      memcpy(key_set->keys[r], dev_0.key, sizeof(dev_0.key));
    }else if(1 == p_access_rule->dev_list[r]){
      memcpy(key_set->keys[r], dev_1.key, sizeof(dev_1.key));
    }else if(2 == p_access_rule->dev_list[r]){
      memcpy(key_set->keys[r], dev_2.key, sizeof(dev_2.key));
    }else if(3 == p_access_rule->dev_list[r]){
      memcpy(key_set->keys[r], dev_3.key, sizeof(dev_3.key));
    }
    else if(4 == p_access_rule->dev_list[r]){

    }
  }

  *pp_key_set = key_set;

  return 0;
}

int sp_km_proc_key_req(const hcp_samp_certificate_t *p_req, kd_samp_package_header_t **response){

  kd_samp_package_header_t *p_resp = NULL;
  sp_aes_gcm_data_t *p_encrypted_keys = NULL;
  sp_samp_key_set_t *p_key_set = NULL;


  /*
    check p_req to judge whether it is a legal health care provider
  */

  if(0 != request_check()){
    return -1;
  }

  /*
    deliver granted device keys to demo_app
  */
  uint8_t hcp_id = 0;
  if(0 != key_access(hcp_id, &p_key_set)){
    return -1;
  }

  // fprintf(stdout, "\nassigned key number: %d \n", p_key_set->key_num);
  // for(uint8_t i =0; i<p_key_set->key_num; i++){
  //   for(uint8_t j = 0; j<16; j++){
  //     fprintf(stdout, "key %d: %d\n", i, p_key_set->keys[i][j]);
  //   }
  //   fprintf(stdout, "*********************\n\n");
  // }

  uint32_t key_set_size = (p_key_set->key_num * sizeof(sample_aes_gcm_128bit_key_t)) + sizeof(sp_samp_key_set_t);

  uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
  p_encrypted_keys = (sp_aes_gcm_data_t *)malloc(sizeof(sp_aes_gcm_data_t) + key_set_size);
  memset(p_encrypted_keys, 0, sizeof(sp_aes_gcm_data_t) + key_set_size);
  if(!p_encrypted_keys){
    fprintf(stderr, "\nError, out of memory in [%s].\n", __FUNCTION__);
    return -1;
  }
  int ret = sample_rijndael128GCM_encrypt(&hcp_0.key,
              &p_key_set->key_num,
              key_set_size,
              p_encrypted_keys->payload,
              &aes_gcm_iv[0],
              SAMPLE_SP_IV_SIZE,
              NULL,
              0,
              &p_encrypted_keys->payload_tag);
  if(SAMPLE_SUCCESS != ret){
    fprintf(stderr, "\nError, data encryption in [%s].\n", __FUNCTION__);
    return -1;
  }

  p_encrypted_keys->payload_size = key_set_size;

  p_resp = (kd_samp_package_header_t *)malloc(sizeof(kd_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + key_set_size);
  if(!p_resp){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(p_resp, 0, sizeof(kd_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + key_set_size);

  p_resp->type = TYPE_KEY_RESPONSE;
  p_resp->size = sizeof(sp_aes_gcm_data_t) + key_set_size;

  memcpy(p_resp->body, p_encrypted_keys, sizeof(sp_aes_gcm_data_t) + key_set_size);

  *response = p_resp;

  return 0;
}
