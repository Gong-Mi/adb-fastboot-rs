// Minimal android-base/logging.h replacement for compiling vendored AOSP
// pairing_auth sources outside the AOSP tree. This file is NOT vendored AOSP
// code; it is a repository-owned compatibility header providing only the
// CHECK macro family used by vendor/adb/pairing_auth/*.cpp.
//
// Semantics match AOSP: CHECK always evaluates and aborts on failure,
// including in release builds.
#pragma once

#include <stdio.h>
#include <stdlib.h>

namespace android {
namespace base {
namespace pairing_shim {

[[noreturn]] inline void CheckFailed(const char* expr, const char* file, int line) {
    fprintf(stderr, "FATAL: CHECK(%s) failed at %s:%d\n", expr, file, line);
    abort();
}

}  // namespace pairing_shim
}  // namespace base
}  // namespace android

#define PAIRING_CHECK_BINOP(a, b, op)                                                     \
    do {                                                                                  \
        if (!((a) op(b))) {                                                               \
            ::android::base::pairing_shim::CheckFailed(#a " " #op " " #b, __FILE__,       \
                                                     __LINE__);                           \
        }                                                                                 \
    } while (0)

#define CHECK(x)                                                                          \
    do {                                                                                  \
        if (!(x)) {                                                                       \
            ::android::base::pairing_shim::CheckFailed(#x, __FILE__, __LINE__);           \
        }                                                                                 \
    } while (0)

#define CHECK_EQ(a, b) PAIRING_CHECK_BINOP(a, b, ==)
#define CHECK_NE(a, b) PAIRING_CHECK_BINOP(a, b, !=)
#define CHECK_GT(a, b) PAIRING_CHECK_BINOP(a, b, >)
#define CHECK_GE(a, b) PAIRING_CHECK_BINOP(a, b, >=)
#define CHECK_LT(a, b) PAIRING_CHECK_BINOP(a, b, <)
#define CHECK_LE(a, b) PAIRING_CHECK_BINOP(a, b, <=)

#define LOG(x) PAIRING_SHIM_LOG_##x
#define PAIRING_SHIM_LOG_ERROR ::android::base::pairing_shim::LogVoid{}
#define PAIRING_SHIM_LOG_WARNING ::android::base::pairing_shim::LogVoid{}
#define PAIRING_SHIM_LOG_INFO ::android::base::pairing_shim::LogVoid{}

namespace android {
namespace base {
namespace pairing_shim {

struct LogVoid {
    template <typename T>
    const LogVoid& operator<<(const T&) const {
        return *this;
    }
};

}  // namespace pairing_shim
}  // namespace base
}  // namespace android
