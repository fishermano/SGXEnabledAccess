#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


#include "policy_management.h"

extern sp_samp_access_rule_t rule_1;

int policy_access(uint8_t hcp_id, sp_samp_access_rule_t **pp_access_rule){

  sp_samp_access_rule_t *access_rule = (sp_samp_access_rule_t *)malloc(sizeof(sp_samp_access_rule_t));
  if(NULL == access_rule){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(access_rule, 0, sizeof(sp_samp_access_rule_t));

  if(0 == hcp_id){
    access_rule->hcp_id = 0;
    access_rule->dev_num = rule_1.dev_num;
    memcpy(&access_rule->dev_list[0], &rule_1.dev_list[0], sizeof(rule_1.dev_list));
  }

  *pp_access_rule = access_rule;

  return 0;

}
