#include <array>
#include <string>
#include "node_bcrypt.h"

#include <iostream>
#include <ostream>

static napi_value validate_salt_sync(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value arg;

    napi_status status = napi_get_cb_info(env, info, &argc, &arg, nullptr, nullptr);
    if (status != napi_ok || argc < 1) {
        napi_throw_error(env, nullptr, "Expected one argument");
        return undefined(env);
    }
    std::string salt = get_string(env, arg);
    if (salt.empty()) {
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

static napi_value generate_salt_sync(napi_env env, napi_callback_info info) {
    constexpr size_t kBcryptSaltChars = 29; // "$2b$12$" + 22-char bcrypt base64 salt

    size_t argc = 3;
    napi_value args[3];

    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != 3) {
        napi_throw_error(env, nullptr, "Expected three argument");
        return undefined(env);
    }

    std::string minor = get_string(env, args[0]);
    if (minor.empty() || minor.length() != 1 || (minor[0] != 'a' && minor[0] != 'b')) {
        napi_throw_error(env, nullptr, "Invalid minor argument");
        return undefined(env);
    }

    uint32_t rounds = get_int32(env, args[1]);
    if (rounds < 4 || rounds > 31) {
        napi_throw_range_error(env, nullptr, "Rounds must be between 4 and 31");
        return undefined(env);
    }

    void *buffer;
    size_t length;
    if (!get_buffer(env, args[2], buffer, length)) {
        return undefined(env);
    }
    if (length < BCRYPT_MAX_SALT) {
        napi_throw_range_error(env, nullptr, "Salt buffer must be at least 16 bytes");
        return undefined(env);
    }

    std::array<char, kBcryptSaltChars + 1> salt{};
    bcrypt_gen_salt(minor[0], rounds, static_cast<u_int8_t *>(buffer), salt.data());

    napi_value result;
    status = napi_create_string_utf8(env, salt.data(), NAPI_AUTO_LENGTH, &result);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create salt string");
        return undefined(env);
    }
    return result;
}

static std::vector<u_int8_t> get_bytes(napi_env env, napi_value value) {
    napi_status status;
    if (is_string(env, value)) {
        size_t size_len;
        status = napi_get_value_string_utf8(env, value, nullptr, 0, &size_len);
        if (status != napi_ok) {
            return {};
        }
        std::vector<u_int8_t> bytes(size_len + 1);

        napi_get_value_string_utf8(env, value, reinterpret_cast<char *>(bytes.data()), bytes.size(), nullptr);

        return bytes;
    }
    if (is_buffer(env, value)) {
        void *buffer;
        size_t length;

        napi_get_buffer_info(env, value, &buffer, &length);
        std::vector<u_int8_t> bytes(static_cast<u_int8_t*>(buffer), static_cast<u_int8_t *>(buffer) + length);
        return bytes;
    }
    return {};
}

static napi_value bcrypt_hash_sync(napi_env env, std::vector<u_int8_t> key, std::vector<u_int8_t> salt) {
    napi_value result;
    try {
        napi_status status;
        std::string hash = bcrypt_hash(std::move(key), std::move(salt));
        status = napi_create_string_utf8(env, hash.c_str(), NAPI_AUTO_LENGTH, &result);
        if (status != napi_ok) {
            napi_throw_error(env, nullptr, "Failed to create hash string");
            return undefined(env);
        }
    } catch (std::exception& e) {
        napi_throw_error(env, nullptr, e.what());
        return undefined(env);
    }
    return result;
}

void bcrypt_hash_async_execute(napi_env env, void *data) {
    auto info = static_cast<bcrypt_info *>(data);
    try {
        auto result = bcrypt_hash(std::move(info->key), std::move(info->salt));
        info->result = std::move(result);
    } catch (std::exception& e) {
        info->result = std::current_exception();
    }
}

void bcrypt_hash_async_complete(napi_env env, napi_status status, void* data) {
    auto info = static_cast<bcrypt_info *>(data);
    if (status == napi_ok && std::holds_alternative<std::string>(info->result)) {
        napi_value result;
        std::string hash_str = std::get<std::string>(info->result);
        napi_create_string_utf8(env, hash_str.c_str(), NAPI_AUTO_LENGTH, &result);
        napi_resolve_deferred(env, info->deferred, result);
    } else {
        std::exception_ptr ex_ptr = std::get<std::exception_ptr>(info->result);
        std::string message = "UNKNOWN_ERROR: An unexpected error occurred";

        try {
            if (ex_ptr) std::rethrow_exception(ex_ptr);
        } catch (const std::runtime_error& e) {
            message = e.what();
        } catch (const std::exception& e) {
            message = e.what();
        }

        std::string code = "UNKNOWN_ERROR";
        size_t delimiter_pos = message.find(": ");
        if (delimiter_pos != std::string::npos) {
            code = message.substr(0, delimiter_pos);
            message = message.substr(delimiter_pos + 2);
        }

        napi_value js_error, js_code, js_msg;
        napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &js_msg);
        napi_create_error(env, nullptr, js_msg, &js_error);

        napi_create_string_utf8(env, code.c_str(), NAPI_AUTO_LENGTH, &js_code);
        napi_set_named_property(env, js_error, "code", js_code);

        napi_reject_deferred(env, info->deferred, js_error);
    }

    napi_delete_async_work(env, info->work);
    delete info;
}

static napi_value bcrypt_hash(napi_env env, napi_callback_info info, bool is_async) {
    size_t argc = 2;
    napi_value args[2];

    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != 2) {
        napi_throw_error(env, nullptr, "Expected two argument");
        return undefined(env);
    }

    auto salt = get_bytes(env, args[0]);
    if (salt.empty() || salt[0] == '\0') {
        napi_throw_type_error(env, nullptr, "Salt must be a string or buffer");
        return undefined(env);
    }

    auto key = get_bytes(env, args[1]);
    if (key.empty() || key[0] == '\0') {
        napi_throw_type_error(env, nullptr, "Key must be a string or buffer");
        return undefined(env);
    }
    if (!is_async) {
        return bcrypt_hash_sync(env, std::move(key), std::move(salt));
    }
    auto *data = new bcrypt_info(std::move(key), std::move(salt), nullptr, nullptr);

    napi_value deferred;
    napi_create_promise(env, &data->deferred, &deferred);

    napi_value work_name;
    napi_create_string_utf8(env, "bcrypt_hash_async", NAPI_AUTO_LENGTH, &work_name);
    napi_create_async_work(env, nullptr, work_name, bcrypt_hash_async_execute, bcrypt_hash_async_complete, data, &data->work);
    napi_queue_async_work(env, data->work);

    return deferred;
}

static napi_value bcrypt_hash_sync(napi_env env, napi_callback_info info) {
    return bcrypt_hash(env, info, false);
}

static napi_value bcrypt_hash_async(napi_env env, napi_callback_info info) {
    return bcrypt_hash(env, info, true);
}

static napi_value init(napi_env env, napi_value exports) {
    napi_status status;
    napi_property_descriptor descriptors[] = {
        { "validateSaltSync", nullptr, validate_salt_sync, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "generateSaltSync", nullptr, generate_salt_sync, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hashSync", nullptr, bcrypt_hash_sync, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hashAsync", nullptr, bcrypt_hash_async, nullptr, nullptr, nullptr, napi_default, nullptr }
    };

    status = napi_define_properties(env, exports, 4, descriptors);
    if (status != napi_ok) {
        return undefined(env);
    }
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);