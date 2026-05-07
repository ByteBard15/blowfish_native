#ifndef NODE_BCRYPT_H_
#define NODE_BCRYPT_H_

#include <exception>
#include <node_api.h>
#include <utility>
#include <vector>
#include <variant>

#include "blowfish.h"

struct bcrypt_info {
	napi_async_work work;
	napi_deferred deferred;
	std::vector<uint8_t> key;
	std::vector<uint8_t> salt;
	std::variant<std::string, std::exception_ptr> result;

	explicit bcrypt_info(std::vector<uint8_t> key, std::vector<uint8_t> salt, napi_deferred deferred, napi_async_work work)
        : work(work), deferred(deferred), key(std::move(key)), salt(std::move(salt)) {}
};

inline napi_value undefined(napi_env env) {
	napi_value result = nullptr;
	napi_get_undefined(env, &result);
	return result;
}

inline napi_value null(napi_env env) {
	napi_value result = nullptr;
	napi_get_null(env, &result);
	return result;
}

inline std::string get_string(napi_env env, napi_value value) {
	napi_valuetype type;
	napi_status status = napi_typeof(env, value, &type);
	if (status != napi_ok || type != napi_string) {
		napi_throw_type_error(env, nullptr, "Expected a string argument");
		return {};
	}

	size_t str_size;
	status = napi_get_value_string_utf8(env, value, nullptr, 0, &str_size);

	if (status != napi_ok) {
		napi_throw_error(env, nullptr, "Failed to get string length");
		return {};
	}

	std::string str(str_size, '\0');
	status = napi_get_value_string_utf8(env, value, str.data(), str_size + 1, nullptr);

	if (status != napi_ok) {
		napi_throw_error(env, nullptr, "Failed to read string argument");
		return {};
	}
	return str;
}

inline size_t get_int32(napi_env env, napi_value value) {
	napi_valuetype type;
	if (napi_typeof(env, value, &type) != napi_ok || type != napi_number) {
		napi_throw_type_error(env, nullptr, "Expected a number");
		return -1;
	}

	int32_t out;
	napi_status status = napi_get_value_int32(env, value, &out);
	if (status != napi_ok) {
		napi_throw_error(env, nullptr, "Failed to read integer");
		return -1;
	}

	return out;
}

inline bool is_buffer(napi_env env, napi_value value) {
	bool is_buffer;
	if (napi_is_buffer(env, value, &is_buffer) != napi_ok || !is_buffer) {
		return false;
	}
	return true;
}

inline bool is_string(napi_env env, napi_value value) {
	napi_valuetype type;
	if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
		return false;
	}
	return true;
}

inline bool get_buffer(napi_env env, napi_value value, void*& data, size_t& length) {
	bool is_buffer;
	if (napi_is_buffer(env, value, &is_buffer) != napi_ok || !is_buffer) {
		napi_throw_type_error(env, nullptr, "Expected a buffer");
		return false;
	}

	napi_status status = napi_get_buffer_info(env, value, &data, &length);
	if (status != napi_ok) {
		napi_throw_error(env, nullptr, "Failed to get buffer info");
		return false;
	}
	return true;
}

#endif
