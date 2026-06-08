#ifndef OPENSSL_HEADER_TARGET_H
#define OPENSSL_HEADER_TARGET_H

#if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
#define OPENSSL_64_BIT
#define OPENSSL_X86_64
#endif

#endif
