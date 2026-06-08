// In-memory TLS 1.3 benchmark matching bench/main.zig categories.
// Build: see bench/compare.sh

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <memory>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

namespace {

constexpr int kIterations = 10000;
constexpr int kTransferBytes = 16384;
constexpr int kTransferIterations = 5000;

static const char kCertPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBzzCCAXagAwIBAgIJANlMBNpJfb/rMAkGByqGSM49BAEwRTELMAkGA1UEBhMC\n"
    "QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp\n"
    "dHMgUHR5IEx0ZDAeFw0xNDA0MjMyMzIxNTdaFw0xNDA1MjMyMzIxNTdaMEUxCzAJ\n"
    "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"
    "dCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmK2ni\n"
    "v2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYa\n"
    "HPUdfvGULUvPciLBo1AwTjAdBgNVHQ4EFgQUq4TSrKuV8IJOFngHVVdf5CaNgtEw\n"
    "HwYDVR0jBBgwFoAUq4TSrKuV8IJOFngHVVdf5CaNgtEwDAYDVR0TBAUwAwEB/zAJ\n"
    "BgcqhkjOPQQBA0gAMEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13E\n"
    "BwIgfB55FGohg/B6dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
    "-----END CERTIFICATE-----\n";

static const char kKeyPEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ\n"
    "TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N\n"
    "Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB\n"
    "-----END PRIVATE KEY-----\n";

using SSLPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
using CTXPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

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

bool ConfigureCtx(SSL_CTX *ctx, bool server) {
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
    return false;
  }
  if (server) {
    return LoadTestCredentials(ctx);
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_NONE, AcceptAny);
  return true;
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

void PrintHeader() {
  std::printf("BoringSSL benchmark (iterations=%d, transfer=%d bytes)\n",
              kIterations, kTransferBytes);
  std::printf("%-50s %12s\n", "benchmark", "result");
  std::printf("%s\n", "----------------------------------------------------------------");
}

void BenchHandshake(CTXPtr &client_ctx, CTXPtr &server_ctx) {
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
  std::printf("%-50s %10.2f /s\n", "full handshake TLS 1.3", handshakes_per_sec);
}

void BenchTransfer(SSL *sender, SSL *receiver, const char *label) {
  uint8_t payload[kTransferBytes];
  std::memset(payload, 'x', sizeof(payload));

  uint8_t wire[kTransferBytes + 4096];

  const int64_t start = NowNanos();
  for (int i = 0; i < kTransferIterations; ++i) {
    const int written =
        SSL_write(sender, payload, static_cast<int>(kTransferBytes));
    if (written != kTransferBytes) {
      std::fprintf(stderr, "SSL_write failed\n");
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
    const int read = SSL_read(receiver, wire, static_cast<int>(sizeof(wire)));
    if (read != kTransferBytes) {
      std::fprintf(stderr, "SSL_read failed (got %d)\n", read);
      ERR_print_errors_fp(stderr);
      std::exit(1);
    }
  }
  const int64_t elapsed_ns = NowNanos() - start;
  const double total_mb =
      static_cast<double>(kTransferBytes) * kTransferIterations / (1024.0 * 1024.0);
  const double mb_per_sec =
      total_mb / (static_cast<double>(elapsed_ns) / 1e9);
  std::printf("%-50s %10.2f MB/s\n", label, mb_per_sec);
}

}  // namespace

int main() {
  CTXPtr client_ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  CTXPtr server_ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  if (!client_ctx || !server_ctx || !ConfigureCtx(client_ctx.get(), false) ||
      !ConfigureCtx(server_ctx.get(), true)) {
    std::fprintf(stderr, "Failed to configure SSL contexts\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  PrintHeader();
  BenchHandshake(client_ctx, server_ctx);

  SSL *client_raw = nullptr;
  SSL *server_raw = nullptr;
  if (!CreatePaired(client_ctx.get(), server_ctx.get(), &client_raw,
                    &server_raw) ||
      !CompleteHandshake(client_raw, server_raw)) {
    std::fprintf(stderr, "Setup connection failed\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }
  SSLPtr client(client_raw, SSL_free);
  SSLPtr server(server_raw, SSL_free);

  BenchTransfer(client.get(), server.get(), "transfer TLS 1.3 send");
  BenchTransfer(server.get(), client.get(), "transfer TLS 1.3 recv");
  return 0;
}
