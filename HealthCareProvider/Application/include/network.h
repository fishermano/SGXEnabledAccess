/*
 * This file defines the format of network package
 * exchanged between the HCP and the trusted broker.
 */

#ifndef _NETWORK_H
#define _NETWORK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PKG_BODY 2046
#define PKG_SIZE 2054

/*
 * Enum for all possible package types.
 */
 typedef enum _pkg_type_t{
    TYPE_RA_MSG0,
    TYPE_RA_MSG1,
    TYPE_RA_MSG2,
    TYPE_RA_MSG3,
    TYPE_RA_ATT_RESULT,
    TYPE_KEY_REQ,
    TYPE_KEY_RES,
    TYPE_HEARTBEAT,
    TYPE_DEVICE_0,
    TYPE_DEVICE_1,
    TYPE_DEVICE_2,
    TYPE_DEVICE_3,
 }pkg_type_t;

/*
 * Define the header of the network package.
 */
 #pragma pack(1)
 typedef struct _pkg_header_t{
   uint8_t type;
   uint32_t size;
   uint8_t reserved[3];
   uint8_t body[];
 }pkg_header_t;

 typedef struct _pkg_t{
   uint8_t type;
   uint32_t size;
   uint8_t reserved[3];
   uint8_t body[1024];
 }pkg_t;
 #pragma pack()

void pkg_serial(const pkg_header_t *pkg_header, char ** pkg);
void pkg_deserial(const char *pkg, pkg_header_t ** pkg_header);

#ifdef __cplusplus
 }
#endif

#endif//_NETWORK_H
