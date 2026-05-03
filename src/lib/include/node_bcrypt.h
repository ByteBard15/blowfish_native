#ifndef NODE_BCRYPT_H_
#define NODE_BCRYPT_H_

#include <node_api.h>
#include "bcrypt.h"

inline napi_value undefined(napi_env env) {
	napi_value result = nullptr;
	napi_get_undefined(env, &result);
	return result;
}

#endif
