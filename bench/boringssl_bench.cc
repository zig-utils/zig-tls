// TLS 1.3 benchmarks aligned with bench/main.zig.
// Canonical transfer rows benchmark one direction each (encrypt or decrypt) on
// TLS 1.3 AES-128-GCM records via EVP_AEAD, matching zig's record crypto path.
// Build: see bench/compare.sh

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <memory>
#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/span.h>
#include <openssl/x509.h>

namespace {

constexpr int kIterations = 10000;
constexpr int kTransferBytes = 16384;
constexpr int kTransferIterations = 5000;
constexpr int kTagLen = 16;
constexpr int kKeyLen128 = 16;
constexpr int kKeyLen256 = 32;
constexpr int kIvLen = 12;

static const char kCertPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfDCCASOgAwIBAgIUQLqOnCo7H/bJUF1Szr+llCjaUDQwCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwODE2NDI0NVoXDTM2MDYwNTE2\n"
    "NDI0NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4G20Q\n"
    "q0dJ3jaRBz8MMglQClooPnY3Z3iNJKNTMFEwHQYDVR0OBBYEFKCBVZdchts7bXZB\n"
    "ZWuL8eNAdz/YMB8GA1UdIwQYMBaAFKCBVZdchts7bXZBZWuL8eNAdz/YMA8GA1Ud\n"
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgcbi5sqviAW6/cB5IceGx2aBG\n"
    "mURelDq3gDVCXdGXhuoCIHgffOqfX89M1r8Hax8HY7MACM+wnevA7UDIurNdCUUU\n"
    "-----END CERTIFICATE-----\n";

static const char kKeyPEM[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIKpmzT0Wdz4OucLI2ZaHsBjBsSLW4rqsmjMoDhmegFKdoAoGCCqGSM49\n"
    "AwEHoUQDQgAEn33K13S5Q8LcxDFMdsmKOFszNXyW7wOyxZfvDxbpa0k5uuzT9ex4\n"
    "G20Qq0dJ3jaRBz8MMglQClooPnY3Z3iNJA==\n"
    "-----END EC PRIVATE KEY-----\n";

using SSLPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
using CTXPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

struct TrafficKeys {
  uint8_t key[32];
  uint8_t iv[kIvLen];
  size_t key_len;
};

int64_t NowNanos() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

bool LoadTestCredentials(SSL_CTX *ctx) {
  BIO *cert_bio = BIO_new_mem_buf(kCertPEM, static_cast<int>(strlen(kCertPEM)));
  BIO *key_bio = BIO_new_mem_buf(kKeyPEM, static_cast<int>(strlen(kKeyPEM)));
  if (!cert_bio || !key_bio) {
    return false;
  }
  X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
  EVP_PKEY *key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
  BIO_free(cert_bio);
  BIO_free(key_bio);
  if (!cert || !key) {
    X509_free(cert);
    EVP_PKEY_free(key);
    return false;
  }
  const bool ok = SSL_CTX_use_certificate(ctx, cert) &&
                  SSL_CTX_use_PrivateKey(ctx, key);
  X509_free(cert);
  EVP_PKEY_free(key);
  return ok;
}

enum ssl_verify_result_t AcceptAny(SSL *ssl, uint8_t *out_alert) {
  (void)ssl;
  (void)out_alert;
  return ssl_verify_ok;
}

bool ConfigureCtx(SSL_CTX *ctx, bool server, bool load_credentials, bool verify_peer) {
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
    return false;
  }
  if (server && load_credentials) {
    if (!LoadTestCredentials(ctx)) {
      return false;
    }
  }
  if (!server) {
    if (verify_peer) {
      X509_STORE *store = X509_STORE_new();
      BIO *cert_bio =
          BIO_new_mem_buf(kCertPEM, static_cast<int>(strlen(kCertPEM)));
      X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
      BIO_free(cert_bio);
      if (!store || !cert || !X509_STORE_add_cert(store, cert)) {
        X509_free(cert);
        X509_STORE_free(store);
        return false;
      }
      X509_free(cert);
      if (!SSL_CTX_set1_verify_cert_store(ctx, store)) {
        X509_STORE_free(store);
        return false;
      }
      X509_STORE_free(store);
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    } else {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
      SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, AcceptAny);
    }
  }
  return true;
}

bool RestrictCipher(SSL_CTX *ctx, const char *cipher) {
  return SSL_CTX_set_strict_cipher_list(ctx, cipher) == 1;
}

bool CreatePaired(SSL_CTX *client_ctx, SSL_CTX *server_ctx, SSL **out_client,
                  SSL **out_server) {
  SSL *client = SSL_new(client_ctx);
  SSL *server = SSL_new(server_ctx);
  if (!client || !server) {
    SSL_free(client);
    SSL_free(server);
    return false;
  }
  SSL_set_connect_state(client);
  SSL_set_accept_state(server);
  SSL_set_shed_handshake_config(client, 1);
  SSL_set_shed_handshake_config(server, 1);

  BIO *bio1 = nullptr;
  BIO *bio2 = nullptr;
  if (!BIO_new_bio_pair(&bio1, 0, &bio2, 0)) {
    SSL_free(client);
    SSL_free(server);
    return false;
  }
  SSL_set_bio(client, bio1, bio1);
  SSL_set_bio(server, bio2, bio2);
  *out_client = client;
  *out_server = server;
  return true;
}

bool CompleteHandshake(SSL *client, SSL *server) {
  for (;;) {
    const int client_ret = SSL_do_handshake(client);
    const int client_err = SSL_get_error(client, client_ret);
    if (client_err != SSL_ERROR_NONE && client_err != SSL_ERROR_WANT_READ &&
        client_err != SSL_ERROR_WANT_WRITE) {
      return false;
    }

    const int server_ret = SSL_do_handshake(server);
    const int server_err = SSL_get_error(server, server_ret);
    if (server_err != SSL_ERROR_NONE && server_err != SSL_ERROR_WANT_READ &&
        server_err != SSL_ERROR_WANT_WRITE) {
      return false;
    }

    if (client_ret == 1 && server_ret == 1) {
      return true;
    }
  }
}

bool Tls13ExpandLabel(uint8_t *out, size_t out_len, const uint8_t *secret,
                      size_t secret_len, const char *label,
                      const uint8_t *context, size_t context_len,
                      const EVP_MD *md) {
  const char prefix[] = "tls13 ";
  const size_t label_len = strlen(label);
  const size_t full_label_len = 6 + label_len;
  uint8_t info[256];
  size_t idx = 0;
  info[idx++] = static_cast<uint8_t>((out_len >> 8) & 0xff);
  info[idx++] = static_cast<uint8_t>(out_len & 0xff);
  info[idx++] = static_cast<uint8_t>(full_label_len);
  std::memcpy(info + idx, prefix, 6);
  idx += 6;
  std::memcpy(info + idx, label, label_len);
  idx += label_len;
  info[idx++] = static_cast<uint8_t>(context_len);
  if (context_len > 0) {
    std::memcpy(info + idx, context, context_len);
    idx += context_len;
  }
  return HKDF_expand(out, out_len, md, secret, secret_len, info, idx) == 1;
}

bool TrafficKeysFromSecret(TrafficKeys *out, bssl::Span<const uint8_t> secret,
                           size_t key_len, const EVP_MD *md) {
  out->key_len = key_len;
  return Tls13ExpandLabel(out->key, key_len, secret.data(), secret.size(),
                          "key", nullptr, 0, md) &&
         Tls13ExpandLabel(out->iv, kIvLen, secret.data(), secret.size(), "iv",
                          nullptr, 0, md);
}

void XorSeqNonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
  std::memcpy(nonce, iv, 12);
  uint64_t be = 0;
  for (int i = 0; i < 8; ++i) {
    be = (be << 8) | nonce[4 + i];
  }
  be ^= seq;
  for (int i = 7; i >= 0; --i) {
    nonce[4 + i] = static_cast<uint8_t>(be & 0xff);
    be >>= 8;
  }
}

void PrintHeader() {
  std::printf("BoringSSL benchmark (iterations=%d, transfer=%d bytes)\n",
              kIterations, kTransferBytes);
  std::printf("%-50s %12s\n", "benchmark", "result");
  std::printf("%s\n", "----------------------------------------------------------------");
}

void BenchHandshake(CTXPtr &client_ctx, CTXPtr &server_ctx, const char *label,
                    bool verify_hostname) {
  {
    SSL *client_raw = nullptr;
    SSL *server_raw = nullptr;
    if (!CreatePaired(client_ctx.get(), server_ctx.get(), &client_raw,
                      &server_raw)) {
      std::fprintf(stderr, "CreatePaired failed\n");
      std::exit(1);
    }
    SSLPtr client(client_raw, SSL_free);
    SSLPtr server(server_raw, SSL_free);
    if (verify_hostname && !SSL_set1_host(client.get(), "localhost")) {
      std::fprintf(stderr, "SSL_set1_host failed\n");
      std::exit(1);
    }
    if (!CompleteHandshake(client.get(), server.get())) {
      std::fprintf(stderr, "Warmup handshake failed\n");
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
  }

  const int64_t start = NowNanos();
  for (int i = 0; i < kIterations; ++i) {
    SSL *client_raw = nullptr;
    SSL *server_raw = nullptr;
    if (!CreatePaired(client_ctx.get(), server_ctx.get(), &client_raw,
                      &server_raw)) {
      std::fprintf(stderr, "CreatePaired failed\n");
      std::exit(1);
    }
    SSLPtr client(client_raw, SSL_free);
    SSLPtr server(server_raw, SSL_free);
    if (verify_hostname && !SSL_set1_host(client.get(), "localhost")) {
      std::fprintf(stderr, "SSL_set1_host failed\n");
      std::exit(1);
    }
    if (!CompleteHandshake(client.get(), server.get())) {
      std::fprintf(stderr, "Handshake failed\n");
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
  }
  const int64_t elapsed_ns = NowNanos() - start;
  const double handshakes_per_sec =
      static_cast<double>(kIterations) /
      (static_cast<double>(elapsed_ns) / 1e9);
  std::printf("%-50s %10.2f /s\n", label, handshakes_per_sec);
}

void BenchRecordCryptoSend(const TrafficKeys &sender_keys, const EVP_AEAD *aead,
                           const char *label) {
  EVP_AEAD_CTX enc_ctx;
  if (!EVP_AEAD_CTX_init(&enc_ctx, aead, sender_keys.key, sender_keys.key_len,
                         kTagLen, nullptr)) {
    std::fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
    std::exit(1);
  }

  alignas(16) uint8_t buf[5 + kTransferBytes + 1 + kTagLen];
  uint8_t *const header = buf;
  uint8_t *const plaintext = buf + 5;
  uint8_t *const ciphertext = buf + 5;
  std::memset(plaintext, 'x', kTransferBytes);
  plaintext[kTransferBytes] = 0x17;

  const uint16_t payload_len =
      static_cast<uint16_t>(kTransferBytes + 1 + kTagLen);
  header[0] = 0x17;
  header[1] = 0x03;
  header[2] = 0x03;
  header[3] = static_cast<uint8_t>(payload_len >> 8);
  header[4] = static_cast<uint8_t>(payload_len & 0xff);

  const size_t ct_len = kTransferBytes + 1;
  uint64_t enc_seq = 0;

  const int64_t start = NowNanos();
  for (int i = 0; i < kTransferIterations; ++i) {
    uint8_t enc_nonce[12];
    XorSeqNonce(enc_nonce, sender_keys.iv, enc_seq);

    size_t sealed_len = 0;
    if (!EVP_AEAD_CTX_seal(&enc_ctx, ciphertext, &sealed_len, ct_len + kTagLen,
                           enc_nonce, sizeof(enc_nonce), plaintext, ct_len,
                           header, 5)) {
      std::fprintf(stderr, "EVP_AEAD_CTX_seal failed\n");
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
    enc_seq++;
  }
  const int64_t elapsed_ns = NowNanos() - start;
  const double total_mb =
      static_cast<double>(kTransferBytes) * kTransferIterations /
      (1024.0 * 1024.0);
  const double mb_per_sec =
      total_mb / (static_cast<double>(elapsed_ns) / 1e9);
  std::printf("%-50s %10.2f MB/s\n", label, mb_per_sec);

  EVP_AEAD_CTX_cleanup(&enc_ctx);
}

void BenchRecordCryptoRecv(const TrafficKeys &sender_keys,
                           const TrafficKeys &receiver_keys,
                           const EVP_AEAD *aead, const char *label) {
  EVP_AEAD_CTX enc_ctx;
  EVP_AEAD_CTX dec_ctx;
  if (!EVP_AEAD_CTX_init(&enc_ctx, aead, sender_keys.key, sender_keys.key_len,
                         kTagLen, nullptr) ||
      !EVP_AEAD_CTX_init(&dec_ctx, aead, receiver_keys.key,
                         receiver_keys.key_len, kTagLen, nullptr)) {
    std::fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
    std::exit(1);
  }

  alignas(16) uint8_t buf[5 + kTransferBytes + 1 + kTagLen];
  uint8_t *const header = buf;
  uint8_t *const plaintext = buf + 5;
  uint8_t *const ciphertext = buf + 5;
  std::memset(plaintext, 'x', kTransferBytes);
  plaintext[kTransferBytes] = 0x17;

  const uint16_t payload_len =
      static_cast<uint16_t>(kTransferBytes + 1 + kTagLen);
  header[0] = 0x17;
  header[1] = 0x03;
  header[2] = 0x03;
  header[3] = static_cast<uint8_t>(payload_len >> 8);
  header[4] = static_cast<uint8_t>(payload_len & 0xff);

  const size_t ct_len = kTransferBytes + 1;
  uint8_t enc_nonce[12];
  XorSeqNonce(enc_nonce, sender_keys.iv, 0);
  size_t sealed_len = 0;
  if (!EVP_AEAD_CTX_seal(&enc_ctx, ciphertext, &sealed_len, ct_len + kTagLen,
                         enc_nonce, sizeof(enc_nonce), plaintext, ct_len,
                         header, 5)) {
    std::fprintf(stderr, "EVP_AEAD_CTX_seal setup failed\n");
    std::exit(1);
  }

  alignas(16) uint8_t cipher_template[5 + kTransferBytes + 1 + kTagLen];
  std::memcpy(cipher_template, buf, sizeof(cipher_template));
  alignas(16) uint8_t work_buf[5 + kTransferBytes + 1 + kTagLen];

  const int64_t start = NowNanos();
  for (int i = 0; i < kTransferIterations; ++i) {
    std::memcpy(work_buf, cipher_template, sizeof(cipher_template));
    uint8_t *const work_header = work_buf;
    uint8_t *const work_plaintext = work_buf + 5;
    uint8_t *const work_ciphertext = work_buf + 5;
    uint8_t dec_nonce[12];
    XorSeqNonce(dec_nonce, receiver_keys.iv, 0);

    size_t opened_len = 0;
    if (!EVP_AEAD_CTX_open(&dec_ctx, work_plaintext, &opened_len, ct_len,
                           dec_nonce, sizeof(dec_nonce), work_ciphertext,
                           ct_len + kTagLen, work_header, 5) ||
        opened_len != ct_len) {
      std::fprintf(stderr, "EVP_AEAD_CTX_open failed\n");
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
  }
  const int64_t elapsed_ns = NowNanos() - start;
  const double total_mb =
      static_cast<double>(kTransferBytes) * kTransferIterations /
      (1024.0 * 1024.0);
  const double mb_per_sec =
      total_mb / (static_cast<double>(elapsed_ns) / 1e9);
  std::printf("%-50s %10.2f MB/s\n", label, mb_per_sec);

  EVP_AEAD_CTX_cleanup(&enc_ctx);
  EVP_AEAD_CTX_cleanup(&dec_ctx);
}


}  // namespace

void BenchTransferSuite(CTXPtr &client_ctx, CTXPtr &server_ctx,
                        const EVP_AEAD *aead, size_t key_len,
                        const EVP_MD *hkdf_md, const char *send_label,
                        const char *recv_label) {
  SSL *client_raw = nullptr;
  SSL *server_raw = nullptr;
  if (!CreatePaired(client_ctx.get(), server_ctx.get(), &client_raw,
                    &server_raw) ||
      !CompleteHandshake(client_raw, server_raw)) {
    std::fprintf(stderr, "Setup connection failed\n");
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
  SSLPtr client(client_raw, SSL_free);
  SSLPtr server(server_raw, SSL_free);

  bssl::Span<const uint8_t> client_read_secret;
  bssl::Span<const uint8_t> client_write_secret;
  bssl::Span<const uint8_t> server_read_secret;
  bssl::Span<const uint8_t> server_write_secret;
  if (!SSL_get_traffic_secrets(client.get(), &client_read_secret,
                               &client_write_secret) ||
      !SSL_get_traffic_secrets(server.get(), &server_read_secret,
                               &server_write_secret)) {
    std::fprintf(stderr, "SSL_get_traffic_secrets failed\n");
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }

  TrafficKeys client_write_keys;
  TrafficKeys server_read_keys;
  if (!TrafficKeysFromSecret(&client_write_keys, client_write_secret, key_len,
                             hkdf_md) ||
      !TrafficKeysFromSecret(&server_read_keys, server_read_secret, key_len,
                             hkdf_md)) {
    std::fprintf(stderr, "TrafficKeysFromSecret failed\n");
    std::exit(1);
  }

  BenchRecordCryptoSend(client_write_keys, aead, send_label);
  BenchRecordCryptoRecv(client_write_keys, server_read_keys, aead, recv_label);
}

int main() {
  CTXPtr client_128(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  CTXPtr client_verify_128(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  CTXPtr server_128(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  CTXPtr client_256(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  CTXPtr server_256(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  if (!client_128 || !client_verify_128 || !server_128 || !client_256 ||
      !server_256 ||
      !ConfigureCtx(client_128.get(), false, false, false) ||
      !ConfigureCtx(client_verify_128.get(), false, false, true) ||
      !ConfigureCtx(server_128.get(), true, true, false) ||
      !ConfigureCtx(client_256.get(), false, false, false) ||
      !ConfigureCtx(server_256.get(), true, true, false) ||
      !RestrictCipher(client_256.get(), "AES256-GCM-SHA384") ||
      !RestrictCipher(server_256.get(), "AES256-GCM-SHA384")) {
    std::fprintf(stderr, "Failed to configure SSL contexts\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  PrintHeader();
  // BoringSSL's TLS 1.3 server requires a certificate; zig-tls also reports a
  // separate minimal (auth=null) row in bench/main.zig.
  BenchHandshake(client_128, server_128, "handshake TLS 1.3 (ECDHE + cert)",
                 false);
  BenchHandshake(client_verify_128, server_128,
                 "handshake TLS 1.3 (ECDHE + cert + verify)", true);

  BenchTransferSuite(client_128, server_128, EVP_aead_aes_128_gcm(),
                     kKeyLen128, EVP_sha256(),
                     "transfer TLS 1.3 record crypto send (AES-128)",
                     "transfer TLS 1.3 record crypto recv (AES-128)");
  BenchTransferSuite(client_256, server_256, EVP_aead_aes_256_gcm(),
                     kKeyLen256, EVP_sha384(),
                     "transfer TLS 1.3 record crypto send (AES-256)",
                     "transfer TLS 1.3 record crypto recv (AES-256)");
  return 0;
}
