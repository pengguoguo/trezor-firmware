/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Fri Jan 10 13:32:02 2020. */

#ifndef PB_ABCKEY_MESSAGES_MNEMONIC_PB_H_INCLUDED
#define PB_ABCKEY_MESSAGES_MNEMONIC_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _reqmnemonic {
    pb_callback_t req;
/* @@protoc_insertion_point(struct:reqmnemonic) */
} reqmnemonic;

typedef struct _rsp_mnemonic {
    pb_callback_t mnemonic;
/* @@protoc_insertion_point(struct:rsp_mnemonic) */
} rsp_mnemonic;

/* Default values for struct fields */

/* Initializer values for message structs */
#define reqmnemonic_init_default                 {{{NULL}, NULL}}
#define rsp_mnemonic_init_default                {{{NULL}, NULL}}
#define reqmnemonic_init_zero                    {{{NULL}, NULL}}
#define rsp_mnemonic_init_zero                   {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define reqmnemonic_req_tag                      1
#define rsp_mnemonic_mnemonic_tag                1

/* Struct field encoding specification for nanopb */
extern const pb_field_t reqmnemonic_fields[2];
extern const pb_field_t rsp_mnemonic_fields[2];

/* Maximum encoded size of messages (where known) */
/* reqmnemonic_size depends on runtime parameters */
/* rsp_mnemonic_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define ABCKEY_MESSAGES_MNEMONIC_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif