#ifndef DEMO_ENCLAVE_T_H__
#define DEMO_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t ecall_close_ra(sgx_ra_context_t context);
sgx_status_t ecall_verify_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t ecall_put_secrets(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);
sgx_status_t ecall_create_sealed_policy(uint8_t* sealed_log, uint32_t sealed_log_size);
sgx_status_t ecall_perform_sealed_policy(const uint8_t* sealed_log, uint32_t sealed_log_size);
sgx_status_t ecall_put_keys(uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t ecall_heartbeat_process(uint8_t* p_hb, uint32_t hb_size, uint8_t* gcm_hb_mac, uint32_t* res_status);
sgx_status_t ecall_perform_statistics(uint8_t* p_secret_1, uint32_t secret_size_1, uint8_t* gcm_mac_1, uint8_t dev_id_1, uint8_t* p_secret_2, uint32_t secret_size_2, uint8_t* gcm_mac_2, uint8_t dev_id_2, uint32_t* result);
sgx_status_t ecall_perform_dec(uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac, uint8_t dev_id);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
