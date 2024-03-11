// Copyright 2001-2023 The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This file contains all the openssl structures, constants 
// and function signatures needed for generating the required
// provider bindings. 

#include <stddef.h>

# define OSSL_PARAM_INTEGER              1
# define OSSL_PARAM_UTF8_PTR             6

/* Functions provided by the provider to the Core, reserved numbers 1024-1535 */
# define OSSL_FUNC_PROVIDER_TEARDOWN           1024
# define OSSL_FUNC_PROVIDER_GETTABLE_PARAMS    1025
# define OSSL_FUNC_PROVIDER_GET_PARAMS         1026
# define OSSL_FUNC_PROVIDER_QUERY_OPERATION    1027
# define OSSL_FUNC_PROVIDER_UNQUERY_OPERATION  1028
# define OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1029
# define OSSL_FUNC_PROVIDER_GET_CAPABILITIES   1030
# define OSSL_FUNC_PROVIDER_SELF_TEST          1031

/* Basic key object creation */
# define OSSL_FUNC_KEYMGMT_NEW                         1
# define OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS       0x80

/* Import and export functions, with discovery */
#define OSSL_FUNC_KEYMGMT_IMPORT                      40
#define OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS             12
#define OSSL_FUNC_KEYMGMT_SET_PARAMS                  13
#define OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS             14

/* Basic key object destruction */
# define OSSL_FUNC_KEYMGMT_FREE                       10

/* Key checks - key data content checks */
# define OSSL_FUNC_KEYMGMT_HAS                        21

/* Operations */

# define OSSL_OP_KEYMGMT                            10

/* Opaque handles to be used with core upcall functions from providers */
typedef struct ossl_core_handle_st OSSL_CORE_HANDLE;

/*
 * Dispatch table element.  function_id numbers and the functions are defined
 * in core_dispatch.h, see macros with 'OSSL_CORE_MAKE_FUNC' in their names.
 *
 * An array of these is always terminated by function_id == 0
 */
struct ossl_dispatch_st {
    int function_id;
    void (*function)(void);
};

typedef struct ossl_dispatch_st OSSL_DISPATCH;

/*
 * Type to pass object data in a uniform way, without exposing the object
 * structure.
 *
 * An array of these is always terminated by key == NULL
 */
struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t return_size;          /* returned content size */
};

typedef struct ossl_param_st OSSL_PARAM;

/*
 * Type to tie together algorithm names, property definition string and
 * the algorithm implementation in the form of a dispatch table.
 *
 * An array of these is always terminated by algorithm_names == NULL
 */
struct ossl_algorithm_st {
    const char *algorithm_names;     /* key */
    const char *property_definition; /* key */
    const OSSL_DISPATCH *implementation;
    const char *algorithm_description;
};

typedef struct ossl_algorithm_st OSSL_ALGORITHM;

OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);

int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val);

int OSSL_PARAM_set_int(OSSL_PARAM *p, int val);
