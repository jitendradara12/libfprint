// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <natasha@natashaee.me>

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
#include <openssl/rand.h>
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

#ifndef fpi_device_emulation_mode_enabled
#define fpi_device_emulation_mode_enabled(dev) (g_getenv ("FP_DEVICE_EMULATION") != NULL)
#endif

static GError *
err_from_ssl (void)
{
  unsigned long code = ERR_get_error ();
  const char *msg = ERR_reason_error_string (code);

  return g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                      "SSL error (0x%lx): %s", code, msg ? msg : "unknown SSL error");
}

#include "goodix5xx.h"

#define GOODIX_TLS_CIPHERS "PSK-AES128-CBC-SHA256:ALL:@SECLEVEL=1"

static unsigned int
tls_server_psk_server_callback (SSL           *ssl,
                                const char    *identity,
                                unsigned char *psk,
                                unsigned int   max_psk_len)
{
  GoodixTlsServer *server = SSL_get_app_data (ssl);

  if (server && server->user_data)
    {
      FpDevice *dev = FP_DEVICE (server->user_data);
      if (FPI_IS_DEVICE_GOODIXTLS5XX (dev))
        {
          FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);
          if (cls && cls->psk && cls->psk_len > 0)
            {
              if (cls->psk_len > max_psk_len)
                {
                  fp_err ("max psk length (%d) too short (needs %d)", max_psk_len, cls->psk_len);
                  return 0;
                }
              memcpy (psk, cls->psk, cls->psk_len);
              fp_dbg ("5e0a PSK callback: using device-specific PSK (%d bytes, identity='%s')",
                      cls->psk_len, identity ? identity : "");
              return cls->psk_len;
            }
        }
      else
        {
          fp_warn ("5e0a PSK callback: dev %p is not GOODIXTLS5XX", dev);
        }
    }
  else
    {
      fp_warn ("5e0a PSK callback: server (%p) or user_data (%p) is NULL",
               server, server ? server->user_data : NULL);
    }

  const int len = 32;

  fp_warn ("5e0a PSK callback: fallback to zero PSK (len %d, max %d)", len, max_psk_len);
  if (len > max_psk_len)
    {
      fp_err ("max psk length (%d) too short (needs %d)", max_psk_len, len);
      return 0;
    }

  // zero out the psk
  for (int n = 0; n != len; ++n)
    psk[n] = 0;

  return len;
}

static SSL_CTX *
tls_server_create_ctx (void)
{
  const SSL_METHOD *method;

  method = TLS_server_method ();

  SSL_CTX *ctx = SSL_CTX_new (method);

  if (!ctx)
    return NULL;

  return ctx;
}

static void
tls_server_config_ctx (SSL_CTX *ctx)
{
  (void) SSL_CTX_set_ecdh_auto (ctx, 1);
  SSL_CTX_set_dh_auto (ctx, 1);
  SSL_CTX_set_cipher_list (ctx, GOODIX_TLS_CIPHERS);
  SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback (ctx, tls_server_psk_server_callback);
}

int
goodix_tls_client_write (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  return write (self->client_fd, data, length * sizeof (guint8));
}
int
goodix_tls_client_read (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  return read (self->client_fd, data, length * sizeof (guint8));
}

int
goodix_tls_server_read (GoodixTlsServer *self, guint8 *data,
                        guint32 length, GError **error)
{
  int retr = SSL_read (self->ssl_layer, data, length * sizeof (guint8));

  if (retr <= 0)
    *error = err_from_ssl ();
  return retr;
}

static void
tls_config_ssl (SSL *ssl)
{
  SSL_set_min_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_max_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_psk_server_callback (ssl, tls_server_psk_server_callback);
  SSL_set_cipher_list (ssl, GOODIX_TLS_CIPHERS);
}

static void *
goodix_tls_init_serve (void *me)
{
  GoodixTlsServer *self = me;

  fp_dbg ("TLS server waiting to accept...");
  int retr = SSL_accept (self->ssl_layer);

  fp_dbg ("TLS server accept done");
  if (retr <= 0)
    {
      unsigned long err_code;
      while ((err_code = ERR_get_error ()) != 0)
        {
          fp_warn ("5e0a TLS accept failed: %s (0x%lx, cipher: %s)",
                   ERR_error_string (err_code, NULL), err_code,
                   SSL_get_cipher_name (self->ssl_layer));
        }
    }
  else
    {
      fp_dbg ("5e0a TLS connection ready (cipher: %s, proto: %s)",
              SSL_get_cipher_name (self->ssl_layer),
              SSL_get_version (self->ssl_layer));
    }
  return NULL;
}

gboolean
goodix_tls_server_deinit (GoodixTlsServer *self, GError **error)
{
  if (!self)
    return TRUE;

  /* First shutdown both socket descriptors.
   * This immediately unblocks any thread in SSL_accept() or read() with EOF. */
  if (self->client_fd >= 0)
    shutdown (self->client_fd, SHUT_RDWR);
  if (self->sock_fd >= 0)
    shutdown (self->sock_fd, SHUT_RDWR);

  /* Now join the serve thread which unblocks instantly */
  if (self->serve_thread)
    {
      pthread_join (self->serve_thread, NULL);
      self->serve_thread = 0;
    }

  /* Close file descriptors after the worker thread has safely exited */
  if (self->client_fd >= 0)
    {
      close (self->client_fd);
      self->client_fd = -1;
    }
  if (self->sock_fd >= 0)
    {
      close (self->sock_fd);
      self->sock_fd = -1;
    }

  if (self->ssl_layer)
    {
      SSL_shutdown (self->ssl_layer);
      SSL_free (self->ssl_layer);
      self->ssl_layer = NULL;
    }

  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  return TRUE;
}

gboolean
goodix_tls_server_init (GoodixTlsServer *self, GError **error)
{
  self->sock_fd = -1;
  self->client_fd = -1;
  self->serve_thread = 0;
  self->ssl_layer = NULL;
  self->ssl_ctx = NULL;

  if (self->user_data && fpi_device_emulation_mode_enabled (FP_DEVICE (self->user_data)))
    {
      static const unsigned char fixed_seed[32] = "goodix5e0a_deterministic_seed_01";
      RAND_seed (fixed_seed, sizeof (fixed_seed));
    }

  SSL_load_error_strings ();
  OpenSSL_add_ssl_algorithms ();
  SSL_library_init ();
  self->ssl_ctx = tls_server_create_ctx ();
  if (self->ssl_ctx == NULL)
    {
      fp_dbg ("Unable to create TLS server context\n");
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Unable to "
                                                                  "create TLS "
                                                                  "server "
                                                                  "context");
      return FALSE;
    }
  tls_server_config_ctx (self->ssl_ctx);

  int socks[2] = {-1, -1};
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, socks) != 0)
    {
      g_set_error (error, G_FILE_ERROR, errno,
                   "failed to create socket pair: %s", strerror (errno));
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
      return FALSE;
    }
  self->sock_fd = socks[0];
  self->client_fd = socks[1];

  self->ssl_layer = SSL_new (self->ssl_ctx);
  SSL_set_app_data (self->ssl_layer, self);
  tls_config_ssl (self->ssl_layer);
  SSL_set_fd (self->ssl_layer, self->sock_fd);

  pthread_create (&self->serve_thread, 0, goodix_tls_init_serve, self);

  return TRUE;
}
