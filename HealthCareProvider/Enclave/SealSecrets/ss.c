#include "../demo_enclave_t.h"
#include "../demo_enclave.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"
#include "string.h"

#define REPLAY_DETECTED             0xF002

#define REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION 5

#define REPLAY_PROTECTED_SECRET_SIZE  32
typedef struct _activity_log
{
    uint32_t release_version;
    uint32_t max_release_version;
}activity_log;

typedef struct _replay_protected_pay_load
{
    sgx_mc_uuid_t mc;
    uint32_t mc_value;
    uint8_t secret[REPLAY_PROTECTED_SECRET_SIZE];
    uint8_t secret_size;
    activity_log log;
}replay_protected_pay_load;

extern uint8_t shared_key[16];
extern uint8_t hb_state;

// Used to store the secret recovered from the outside. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
extern uint8_t u_shared_key[16];

static sgx_status_t verify_mc(replay_protected_pay_load* data2verify)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint32_t mc_value;
    ret = sgx_read_monotonic_counter(&data2verify->mc,&mc_value);
    if(ret != SGX_SUCCESS)
    {
        switch(ret)
        {
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            /* Architecture Enclave Service Manager is not installed or not
            working properly.*/
                break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            /* retry the operation later*/
                break;
        case SGX_ERROR_BUSY:
            /* retry the operation later*/
                break;
        case SGX_ERROR_MC_NOT_FOUND:
            /* the the Monotonic Counter ID is invalid.*/
                break;
        default:
            /*other errors*/
            break;
        }
    }
    else if(mc_value!=data2verify->mc_value)
    {
        ret = (sgx_status_t)REPLAY_DETECTED;
    }
    return ret;
}

static sgx_status_t verify_sealed_data(
    const sgx_sealed_data_t* data2unseal,
    replay_protected_pay_load* data_unsealed)
{
    sgx_status_t ret = SGX_SUCCESS;
    replay_protected_pay_load temp_unseal;
    uint32_t unseal_length = sizeof(replay_protected_pay_load);

    ret = sgx_unseal_data(data2unseal, NULL, 0,
        (uint8_t*)&temp_unseal, &unseal_length);
    if(ret != SGX_SUCCESS)
    {
        switch(ret)
        {
        case SGX_ERROR_MAC_MISMATCH:
            /* MAC of the sealed data is incorrect.
            The sealed data has been tampered.*/
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            /*Indicates attribute field of the sealed data is incorrect.*/
            break;
        case SGX_ERROR_INVALID_ISVSVN:
            /* Indicates isv_svn field of the sealed data is greater than
            the enclave's ISVSVN. This is a downgraded enclave.*/
            break;
        case SGX_ERROR_INVALID_CPUSVN:
            /* Indicates cpu_svn field of the sealed data is greater than
            the platform's cpu_svn. enclave is  on a downgraded platform.*/
            break;
        case SGX_ERROR_INVALID_KEYNAME:
            /*Indicates key_name field of the sealed data is incorrect.*/
            break;
        default:
            /*other errors*/
            break;
        }
        return ret;
    }
    ret = verify_mc(&temp_unseal);
    if (ret == SGX_SUCCESS)
        memcpy(data_unsealed,&temp_unseal,sizeof(replay_protected_pay_load));
    /* remember to clear secret data after been used by memset_s */
    memset(&temp_unseal, 0,
        sizeof(replay_protected_pay_load));
    return ret;
}

sgx_status_t ecall_create_sealed_policy(uint8_t* sealed_log, uint32_t sealed_log_size){
  ocall_print("testing enclave function: ecall_create_sealed_policy()");

  // if(STATUS_HB_ACTIVE != hb_state){
  //   ocall_print("\nHeartbeat mechanism is not active, please make sure to active it by revoking ecall_start_heartbeat()\n");
  //
  //   return SGX_ERROR_UNEXPECTED;
  // }

  sgx_status_t ret = SGX_SUCCESS;
  int busy_retry_times = 2;
  replay_protected_pay_load data2seal;
  memset(&data2seal, 0, sizeof(data2seal));
  uint32_t size = sgx_calc_sealed_data_size(0, sizeof(replay_protected_pay_load));
  if(sealed_log_size != size){
    return SGX_ERROR_INVALID_PARAMETER;
  }
  do{
    ret = sgx_create_pse_session();
  }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
  if(SGX_SUCCESS != ret){
    return ret;
  }

  do{
    ret = sgx_create_monotonic_counter(&data2seal.mc,&data2seal.mc_value);
    if(SGX_SUCCESS != ret){
      switch(ret){
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            /* Architecture Enclave Service Manager is not installed or not
            working properly.*/
            break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            /* retry the operation later*/
            break;
        case SGX_ERROR_BUSY:
            /* retry the operation later*/
            break;
        case SGX_ERROR_MC_OVER_QUOTA:
            /* SGX Platform Service enforces a quota scheme on the Monotonic
            Counters a SGX app can maintain. the enclave has reached the
            quota.*/
            break;
        case SGX_ERROR_MC_USED_UP:
            /* the Monotonic Counter has been used up and cannot create
            Monotonic Counter anymore.*/
            break;
        default:
            /*other errors*/
            break;
      }
      break;
    }

    /* secret should be provisioned into enclave after the enclave attests to
    the secret owner.
    For example, the server that delivers the encrypted DRM content.
    In this sample code, a random number is used to represent the secret */
    // ret = sgx_read_rand(data2seal.secret, REPLAY_PROTECTED_SECRET_SIZE);
    // if(SGX_SUCCESS != ret){
    //     break;
    // }

    memcpy(data2seal.secret, shared_key, sizeof(shared_key));
    data2seal.secret_size = sizeof(shared_key);

    data2seal.log.release_version = 0;
    /* the secret can be updated for 5 times */
    data2seal.log.max_release_version =
        REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION;

    /*sealing the plaintext to ciphertext. The ciphertext can be delivered
    outside of enclave.*/
    ret = sgx_seal_data(0, NULL,sizeof(data2seal),(uint8_t*)&data2seal,
        sealed_log_size, (sgx_sealed_data_t*)sealed_log);
  } while (0);

  memset(&shared_key, 0, sizeof(shared_key));
  memset(&data2seal, 0, sizeof(replay_protected_pay_load));

  sgx_close_pse_session();

  return ret;
}

sgx_status_t ecall_perform_sealed_policy(const uint8_t* sealed_log, uint32_t sealed_log_size){
  ocall_print("\ntesting enclave function: ecall_perform_sealed_policy()");

  // if(STATUS_HB_ACTIVE != hb_state){
  //   ocall_print("\nHeartbeat mechanism is not active, please make sure to active it by revoking ecall_start_heartbeat()\n");
  //
  //   return SGX_ERROR_UNEXPECTED;
  // }

  sgx_status_t ret = SGX_SUCCESS;
  int busy_retry_times = 2;

  replay_protected_pay_load data_unsealed;
  if(sealed_log_size != sgx_calc_sealed_data_size(0, sizeof(replay_protected_pay_load))){
    return SGX_ERROR_INVALID_PARAMETER;
  }

  do{
    ret = sgx_create_pse_session();
  }while(SGX_ERROR_BUSY == ret && busy_retry_times--);

  if(SGX_SUCCESS != ret){
    return ret;
  }

  ret = verify_sealed_data((const sgx_sealed_data_t*) sealed_log, &data_unsealed);

  if (SGX_SUCCESS != ret){
    /* activity log update fail to verify activity log,
    refuse to release the secret */
    sgx_close_pse_session();
    return ret;
  }

  sgx_close_pse_session();

  memcpy(u_shared_key, data_unsealed.secret, data_unsealed.secret_size);

  // uint32_t i;
  // for(i=0;i<sizeof(u_shared_key);i++){
  //     ocall_print_int(u_shared_key[i]);
  // }

  /* remember to clear secret data after been used by memset_s */
  memset(&data_unsealed, 0, sizeof(replay_protected_pay_load) );

  return ret;
}
