#ifndef OPENSSL_HEADER_ASM_BASE_H
#define OPENSSL_HEADER_ASM_BASE_H

#include <openssl/target.h>

#if defined(__ASSEMBLER__)

#if !defined(__ARM_ARCH)
#define __ARM_ARCH 8
#endif

#define __ARM_MAX_ARCH__ 8

#define AARCH64_VALID_CALL_TARGET
#define AARCH64_SIGN_LINK_REGISTER
#define AARCH64_VALIDATE_LINK_REGISTER

#endif

#endif
