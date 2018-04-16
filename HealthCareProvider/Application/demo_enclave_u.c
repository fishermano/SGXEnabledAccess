#include "demo_enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_ecall_init_ra_t;

typedef struct ms_ecall_close_ra_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_ecall_close_ra_t;

typedef struct ms_ecall_verify_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_ecall_verify_result_mac_t;

typedef struct ms_ecall_put_secrets_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_ecall_put_secrets_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ecall_create_sealed_policy_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_ecall_create_sealed_policy_t;

typedef struct ms_ecall_perform_sealed_policy_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_ecall_perform_sealed_policy_t;

typedef struct ms_ecall_put_keys_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_ecall_put_keys_t;

typedef struct ms_ecall_heartbeat_process_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_hb;
	uint32_t ms_hb_size;
	uint8_t* ms_gcm_hb_mac;
} ms_ecall_heartbeat_process_t;

typedef struct ms_ecall_perform_statistics_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_secret_1;
	uint32_t ms_secret_size_1;
	uint8_t* ms_gcm_mac_1;
	uint8_t ms_dev_id_1;
	uint8_t* ms_p_secret_2;
	uint32_t ms_secret_size_2;
	uint8_t* ms_gcm_mac_2;
	uint8_t ms_dev_id_2;
	uint32_t* ms_result;
} ms_ecall_perform_statistics_t;

typedef struct ms_ecall_evaluate_decryption_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_files;
	uint32_t ms_file_number;
	uint32_t ms_total_size;
} ms_ecall_evaluate_decryption_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_int_t {
	int ms_num;
} ms_ocall_print_int_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL demo_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_ocall_print_int(void* pms)
{
	ms_ocall_print_int_t* ms = SGX_CAST(ms_ocall_print_int_t*, pms);
	ocall_print_int(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL demo_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[11];
} ocall_table_demo_enclave = {
	11,
	{
		(void*)demo_enclave_ocall_print,
		(void*)demo_enclave_ocall_print_int,
		(void*)demo_enclave_create_session_ocall,
		(void*)demo_enclave_exchange_report_ocall,
		(void*)demo_enclave_close_session_ocall,
		(void*)demo_enclave_invoke_service_ocall,
		(void*)demo_enclave_sgx_oc_cpuidex,
		(void*)demo_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)demo_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)demo_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)demo_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_ecall_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 0, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_close_ra(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_ecall_close_ra_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_verify_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_ecall_verify_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 2, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_put_secrets(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_ecall_put_secrets_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 3, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 4, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 5, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 6, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_sealed_policy(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_log, uint32_t sealed_log_size)
{
	sgx_status_t status;
	ms_ecall_create_sealed_policy_t ms;
	ms.ms_sealed_log = sealed_log;
	ms.ms_sealed_log_size = sealed_log_size;
	status = sgx_ecall(eid, 7, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_perform_sealed_policy(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_log, uint32_t sealed_log_size)
{
	sgx_status_t status;
	ms_ecall_perform_sealed_policy_t ms;
	ms.ms_sealed_log = (uint8_t*)sealed_log;
	ms.ms_sealed_log_size = sealed_log_size;
	status = sgx_ecall(eid, 8, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_put_keys(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_ecall_put_keys_t ms;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 9, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_heartbeat_process(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_hb, uint32_t hb_size, uint8_t* gcm_hb_mac)
{
	sgx_status_t status;
	ms_ecall_heartbeat_process_t ms;
	ms.ms_p_hb = p_hb;
	ms.ms_hb_size = hb_size;
	ms.ms_gcm_hb_mac = gcm_hb_mac;
	status = sgx_ecall(eid, 10, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_perform_statistics(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_secret_1, uint32_t secret_size_1, uint8_t* gcm_mac_1, uint8_t dev_id_1, uint8_t* p_secret_2, uint32_t secret_size_2, uint8_t* gcm_mac_2, uint8_t dev_id_2, uint32_t* result)
{
	sgx_status_t status;
	ms_ecall_perform_statistics_t ms;
	ms.ms_p_secret_1 = p_secret_1;
	ms.ms_secret_size_1 = secret_size_1;
	ms.ms_gcm_mac_1 = gcm_mac_1;
	ms.ms_dev_id_1 = dev_id_1;
	ms.ms_p_secret_2 = p_secret_2;
	ms.ms_secret_size_2 = secret_size_2;
	ms.ms_gcm_mac_2 = gcm_mac_2;
	ms.ms_dev_id_2 = dev_id_2;
	ms.ms_result = result;
	status = sgx_ecall(eid, 11, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_evaluate_decryption(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_files, uint32_t file_number, uint32_t total_size)
{
	sgx_status_t status;
	ms_ecall_evaluate_decryption_t ms;
	ms.ms_p_files = p_files;
	ms.ms_file_number = file_number;
	ms.ms_total_size = total_size;
	status = sgx_ecall(eid, 12, &ocall_table_demo_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

