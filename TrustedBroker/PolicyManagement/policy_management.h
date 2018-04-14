#ifndef POLICY_MANAGEMENT
#define POLICY_MANAGEMENT

#include <stdint.h>

#define MAX_DEV_NUM 8

typedef struct _sp_samp_access_rule_t{
  uint8_t hcp_id;
  uint8_t dev_num;
  uint8_t dev_list[MAX_DEV_NUM];
}sp_samp_access_rule_t;

int sp_define_policy(uint8_t hcp_id, uint8_t dev_list[]);

int policy_access(uint8_t hcp_id, sp_samp_access_rule_t **pp_access_rule);

#endif
