// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>

#include "drivers_api.h"
#include "fp-device.h"
#include "fpi-device.h"
#include "glibconfig.h"
#include "goodix.h"
#include "goodixtls.h"

static GError *err_from_ssl(void) {
  GError *err = malloc(sizeof(GError));
  unsigned long code = ERR_get_error();

  err->code = code;
  const char *msg = ERR_reason_error_string(code);

  err->message = malloc(strlen(msg));
  strcpy(err->message, msg);
  return err;
}

static unsigned int tls_server_psk_server_callback(SSL *ssl,
                                                   const char *identity,
                                                   unsigned char *psk,
                                                   unsigned int max_psk_len) {
  if (sizeof(goodix_511_psk_0) > max_psk_len) {
    fp_dbg("Provided PSK R is too long for OpenSSL");
    return 0;
  }
  fp_dbg("PSK WANTED %d", max_psk_len);
  // I don't know why we must use OPENSSL_hexstr2buf but just copying zeros
  // doesn't work
  const char *buff =
      "267c516855454d296b26525a5f66356c376a246b5a454c307c377a3d746c2446";
  long len = 0;
  unsigned char *key = OPENSSL_hexstr2buf(buff, &len);
  memcpy(psk, key, len);
  OPENSSL_free(key);

  return len;
}

static SSL_CTX *tls_server_create_ctx(void) {
  const SSL_METHOD *method;

  method = TLS_server_method();

  SSL_CTX *ctx = SSL_CTX_new(method);

  return ctx;
}

static void tls_server_config_ctx(SSL_CTX *ctx) {
  SSL_CTX_set_ecdh_auto(ctx, 1);
  SSL_CTX_set_dh_auto(ctx, 1);
  SSL_CTX_set_cipher_list(ctx, "ALL");
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback(ctx, tls_server_psk_server_callback);
}

int goodix_tls_client_send(GoodixTlsServer *self, guint8 *data,
                           guint16 length) {
  return write(self->client_fd, data, length * sizeof(guint8));
}
int goodix_tls_client_recv(GoodixTlsServer *self, guint8 *data,
                           guint16 length) {
  return read(self->client_fd, data, length * sizeof(guint8));
}

int goodix_tls_server_receive(GoodixTlsServer *self, guint8 *data,
                              guint32 length, GError **error) {
  int retr = SSL_read(self->ssl_layer, data, length * sizeof(guint8));
  if (retr <= 0) {
    *error = err_from_ssl();
  }
  return retr;
}

static void tls_config_ssl(SSL *ssl) {
  SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
  SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
  SSL_set_psk_server_callback(ssl, tls_server_psk_server_callback);
  SSL_set_cipher_list(ssl, "ALL");
}

static void *goodix_tls_init_serve(void *me) {
  GoodixTlsServer *self = me;

  fp_dbg("TLS server waiting to accept...");
  int retr = SSL_accept(self->ssl_layer);

  fp_dbg("TLS server accept done");
  if (retr <= 0)
    self->connection_callback(self, err_from_ssl(), self->user_data);
  else
    self->connection_callback(self, NULL, self->user_data);
  return NULL;
}

gboolean goodix_tls_server_deinit(GoodixTlsServer *self, GError **error) {
  SSL_shutdown(self->ssl_layer);
  SSL_free(self->ssl_layer);

  close(self->client_fd);
  close(self->sock_fd);

  SSL_CTX_free(self->ssl_ctx);

  return TRUE;
}

gboolean goodix_tls_server_init(GoodixTlsServer *self, GError **error) {
  g_assert(self->connection_callback);
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  SSL_library_init();
  self->ssl_ctx = tls_server_create_ctx();
  tls_server_config_ctx(self->ssl_ctx);

  int socks[2] = {0, 0};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0) {
    g_set_error(error, G_FILE_ERROR, errno, "failed to create socket pair: %s",
                strerror(errno));
    return FALSE;
  }
  self->sock_fd = socks[0];
  self->client_fd = socks[1];

  if (self->ssl_ctx == NULL) {
    fp_dbg("Unable to create TLS server context\n");
    *error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
                                      "Unable to "
                                      "create TLS "
                                      "server "
                                      "context");
    return FALSE;
  }
  self->ssl_layer = SSL_new(self->ssl_ctx);
  tls_config_ssl(self->ssl_layer);
  SSL_set_fd(self->ssl_layer, self->sock_fd);

  pthread_create(&self->serve_thread, 0, goodix_tls_init_serve, self);

  return TRUE;
}

gboolean goodix_derive_whitebox(const guint8 *psk, guint16 length,
                                guint8 *psk_wb, guint16 *psk_wb_length,
                                GError **error) {
  const guint8 goodix_const[] = {0x5c, 0xba, 0x6e, 0x25, 0x81, 0x95,
                                        0x18, 0xde, 0x2d, 0x53, 0xe9,
                                        0x6d, 0xc0, 0x34, 0x7a, 0xb0};
  guint8 nonce[16];
  guint8 shabuf[64] = {0};
  guint8 keys[32];
  guint8 padded[48];
  guint8 encrypted[48];
  guint8 signature[32];
  guint8 aeskey[16];
  EVP_CIPHER_CTX *ctx;
  EVP_MAC *mac;
  EVP_MAC_CTX *mac_ctx;
  EVP_MD_CTX *md_ctx;
  int len, padded_len, enc_len;
  guint32 md_len;
  guint64 mac_len;
  // generate nonce
  RAND_bytes(nonce, 16);
  // construct SHA input
  memcpy(shabuf, nonce, sizeof(nonce));

  // SHA256(shabuf + constant)
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == NULL) {
    g_print("Failed to create MD context\n");
    return FALSE;
  }
  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(md_ctx, shabuf, sizeof(shabuf)) != 1 ||
      EVP_DigestUpdate(md_ctx, goodix_const, sizeof(goodix_const)) != 1 ||
      EVP_DigestFinal_ex(md_ctx, keys, &md_len) != 1) {
    EVP_MD_CTX_free(md_ctx);
    g_print("SHA256 digest failed\n");
    return FALSE;
  }
  EVP_MD_CTX_free(md_ctx);
  memcpy(aeskey, keys, sizeof(aeskey));
  // PKCS7 padding
  int pad_len = 16 - (length % 16);
  padded_len = length + pad_len;

  // Copy original data
  memcpy(padded, psk, length);

  // Add PKCS7 padding
  for (int i = 0; i < pad_len; i++) {
    padded[length + i] = pad_len;
  }

  // AES-128-CBC encryption
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    g_print("Failed to create cipher context\n");
    return FALSE;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aeskey, nonce) != 1 ||
      EVP_EncryptUpdate(ctx, encrypted, &len, padded, padded_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    g_print("AES encryption failed\n");
    return FALSE;
  }
  enc_len = len;
  g_print("Encrypted data length: %d\n", enc_len);
  if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    g_print("AES encryption finalization failed\n");
    return FALSE;
  }
  EVP_CIPHER_CTX_free(ctx);

  // HMAC signing
  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (mac == NULL) {
    g_print("Failed to fetch HMAC\n");
    return FALSE;
  }

  mac_ctx = EVP_MAC_CTX_new(mac);
  if (mac_ctx == NULL) {
    EVP_MAC_free(mac);
    g_print("Failed to create MAC context\n");
    return FALSE;
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
      OSSL_PARAM_construct_end()};

  if (EVP_MAC_init(mac_ctx, keys, 32, params) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_print("HMAC initialization failed\n");
    return FALSE;
  }

  if (EVP_MAC_update(mac_ctx, encrypted, enc_len) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_print("HMAC update failed\n");
    return FALSE;
  }

  if (EVP_MAC_final(mac_ctx, signature, &mac_len, sizeof(signature)) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_print("HMAC finalization failed\n");
    return FALSE;
  }

  EVP_MAC_CTX_free(mac_ctx);
  EVP_MAC_free(mac);

  // Combine results: nonce + encrypted + signature
  memcpy(psk_wb, nonce, 16);
  memcpy(psk_wb + 16, encrypted, enc_len);
  memcpy(psk_wb + 16 + enc_len, signature, mac_len);
  *psk_wb_length = 16 + enc_len + mac_len;

  return TRUE;
}

gboolean goodix_derive_pmk_hash(const guint8 *psk, guint16 length,
                                guint8 *pmk_hash, guint16 *pmk_hash_length,
                                GError **error) {
  EVP_MD_CTX *md_ctx;
  EVP_MAC *mac;
  EVP_MAC_CTX *mac_ctx;
  guint8 pmk[32];
  guint32 md_len;
  guint64 hmac_len;
  const guint8 rawpmk_prefix[] = {
      0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20};
  const guint8 magic_nums[] = {
      0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 0x37, 0x36, 0x35,
      0x34, 0x33, 0x32, 0x31, 0x30, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a,
      0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1f,
      0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14,
      0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
  guint8 rawpmk[68];

  memcpy(rawpmk, rawpmk_prefix, sizeof(rawpmk_prefix));
  memcpy(rawpmk + sizeof(rawpmk_prefix), psk, length);
  // 计算PMK哈希
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to create MD context");
    return FALSE;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(md_ctx, rawpmk, sizeof(rawpmk_prefix) + length) != 1 ||
      EVP_DigestFinal_ex(md_ctx, pmk, &md_len) != 1) {
    EVP_MD_CTX_free(md_ctx);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "SHA256 computation failed");
    return FALSE;
  }
  EVP_MD_CTX_free(md_ctx);
  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (mac == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to fetch HMAC");
    return FALSE;
  }

  mac_ctx = EVP_MAC_CTX_new(mac);
  if (mac_ctx == NULL) {
    EVP_MAC_free(mac);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to create MAC context");
    return FALSE;
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
      OSSL_PARAM_construct_end()};

  if (EVP_MAC_init(mac_ctx, pmk, md_len, params) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "HMAC initialization failed");
    return FALSE;
  }
  if (EVP_MAC_update(mac_ctx, magic_nums, sizeof(magic_nums)) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "HMAC update failed");
    return FALSE;
  }
  if (EVP_MAC_final(mac_ctx, pmk_hash, &hmac_len, 32) != 1) {
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "HMAC finalization failed");
    return FALSE;
  }
  *pmk_hash_length = hmac_len;
  EVP_MAC_CTX_free(mac_ctx);
  EVP_MAC_free(mac);
  return TRUE;
}
