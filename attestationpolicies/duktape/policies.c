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

#include <stdio.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <math.h>

#include "duktape.h"

// required because duktape does not provide I/O bindings
static duk_ret_t native_print(duk_context *ctx) {
    printf("%s\n", duk_to_string(ctx, 0));
    return 0;
}

bool Validate(uint8_t *ar, size_t ar_size, uint8_t *policies, size_t policies_size) {

    char ar_str[ar_size+1];
    memcpy(ar_str, ar, ar_size);
    ar_str[ar_size] = '\0';

    char policies_str[policies_size+1];
    memcpy(policies_str, policies, policies_size);
    policies_str[policies_size] = '\0';

    duk_context *ctx = duk_create_heap_default();

    duk_push_c_function(ctx, native_print, 1);
    duk_put_global_string(ctx, "print");

    // Push attestation result as a string
    duk_push_global_object(ctx);
    duk_push_string(ctx, "json");
    duk_push_string(ctx, (const char  *)ar_str);
    duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_VALUE);

    // Run policies
    duk_eval_string(ctx, policies_str);
    bool success = (bool)duk_get_boolean(ctx, -1);
    printf("Duktape Policy Verification: %s\n", success ? "SUCCESS" : "FAIL");

    duk_destroy_heap(ctx);

    return success;
}
