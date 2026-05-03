#include <string>

#include "blowfish.h"
#include "node_bcrypt.h"

static napi_value validate_salt_value(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value arg;

    napi_status status = napi_get_cb_info(env, info, &argc, &arg, nullptr, nullptr);
    if (status != napi_ok || argc < 1) {
        napi_throw_error(env, nullptr, "Expected one argument");
        return undefined(env);
    }

    napi_valuetype type;
    status = napi_typeof(env, arg, &type);
    if (status != napi_ok || type != napi_string) {
        napi_throw_type_error(env, nullptr, "Expected a string argument");
        return undefined(env);
    }

    std::string salt;
    status = napi_get_value_string_utf8(env, arg, const_cast<char *>(salt.c_str()), NAPI_AUTO_LENGTH, nullptr);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to read string argument");
        return undefined(env);
    }

    if (salt.empty()) {
        napi_throw_range_error(env, nullptr, "Salt string cannot be empty");
        return undefined(env);
    }
    bool is_valid = validate_salt(salt.c_str());
    napi_value result;

    status = napi_get_boolean(env, is_valid, &result);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create boolean result");
        return undefined(env);
    }

    return result;
}

static napi_value init(napi_env env, napi_value exports) {
    napi_status status;
    napi_property_descriptor descriptors[] = {
        { "validateSalt", nullptr, validate_salt_value, nullptr, nullptr, nullptr, napi_default, nullptr }
    };

    status = napi_define_properties(env, exports, 1, descriptors);
    if (status != napi_ok) {
        return nullptr;
    }
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);