// Copyright (c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <math.h>
#include <string.h>

#include "duktape.h"

// required because duktape does not provide I/O bindings
static duk_ret_t native_print(duk_context *ctx) {
    printf("%s\n", duk_to_string(ctx, 0));
    return 0;
}

char* Validate(uint8_t *ar, size_t ar_size, uint8_t *policies, size_t policies_size) {
    char ar_str[ar_size + 1];
    memcpy(ar_str, ar, ar_size);
    ar_str[ar_size] = '\0';

    char policies_str[policies_size + 1];
    memcpy(policies_str, policies, policies_size);
    policies_str[policies_size] = '\0';

    duk_context *ctx = duk_create_heap_default();

    // Optional: provide print() in JS
    duk_push_c_function(ctx, native_print, 1);
    duk_put_global_string(ctx, "print");

    // Push `json` variable for policy
    duk_push_global_object(ctx);
    duk_push_string(ctx, "json");
    duk_push_string(ctx, ar_str);
    duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_VALUE);

    // Evaluate policies
    if (duk_peval_string(ctx, policies_str) != 0) {
        const char *err = duk_safe_to_string(ctx, -1);
        fprintf(stderr, "Policy error: %s\n", err);
        duk_destroy_heap(ctx);
        return strdup("false");
    }

    // Convert result to string
    const char *result_str = duk_safe_to_string(ctx, -1);
    char *ret = strdup(result_str);

    duk_destroy_heap(ctx);
    return ret;
}
