// Minimal android-base/endian.h replacement for compiling vendored AOSP
// sources outside the AOSP tree. Repository-owned compatibility header;
// forwards to the platform endian headers. The vendored pairing_auth sources
// include this header but do not call any of its functions.
#pragma once

#if defined(__ANDROID__)
#include <endian.h>
#include <sys/endian.h>
#else
#include <endian.h>
#endif
