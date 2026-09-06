// Goodix TLS driver for libfprint - 27c6:5e0a (Realme Book / ChicagoH)
// Clean-room reverse engineering from passive USB captures of Windows driver traffic.

// Copyright (C) 2026 The libfprint Goodix 5e0a contributors

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

#include "drivers/goodixtls/goodix5xx.h"
#include "fp-device.h"
#include "fp-image-device.h"
#include "fp-image.h"
#include "fpi-assembling.h"
#include "fpi-context.h"
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "fpi-ssm.h"
#include "glibconfig.h"
#include "gusb/gusb-device.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define FP_COMPONENT "goodixtls5e0a"

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "drivers_api.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include "nbis/include/lfs.h"
#pragma GCC diagnostic pop
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix5e0a.h"

struct _FpiDeviceGoodixTls5e0a
{
  FpiDeviceGoodixTls5xx parent;

  gboolean              session_started;
  FpiSsm               *scan_ssm;
  GSource              *down_timeout;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a, FPI,
                      DEVICE_GOODIXTLS5E0A, FpiDeviceGoodixTls5xx);

G_DEFINE_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a,
               FPI_TYPE_DEVICE_GOODIXTLS5XX);

// ---- ACTIVATE SECTION START ----

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_RESET,
  ACTIVATE_READ_CHIP_ID,
  ACTIVATE_READ_OTP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_UPLOAD_CONFIG,
  ACTIVATE_DIAG_READ_PSK,
  ACTIVATE_NUM_STATES,
};

/* [DIAG-5E0A] TEMPORARY 0xe4 slot read, diagnosis only, remove before merge.
 * Compares the device-visible PSK slot against the static host key and logs
 * the verdict WITHOUT altering activation (always advances). A mismatch here
 * proves out-of-band device-side reprovisioning (or SRAM key loss) when TLS
 * later fails with bad-record-mac. Grep DIAG-5E0A to remove. */
static void
diag_psk_read_cb (FpDevice *dev, gboolean success, guint32 flags,
                  guint8 *psk, guint16 length, gpointer user_data,
                  GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_dbg ("[DIAG-5E0A] psk-slot read failed: %s", error->message);
      g_error_free (error);
      fpi_ssm_next_state (ssm);
      return;
    }

  if (!success)
    {
      fp_dbg ("[DIAG-5E0A] psk-slot read returned success=FALSE");
      fpi_ssm_next_state (ssm);
      return;
    }

  g_autofree gchar *slot_hex = data_to_str (psk, length);
  g_autofree gchar *host_hex = data_to_str ((guint8 *) goodix_5e0a_psk,
                                            sizeof (goodix_5e0a_psk));

  if (length == sizeof (goodix_5e0a_psk) &&
      memcmp (psk, goodix_5e0a_psk, sizeof (goodix_5e0a_psk)) == 0)
    fp_dbg ("[DIAG-5E0A] psk-slot MATCHES static host key (flags=0x%08x len=%u)",
            flags, length);
  else
    fp_warn ("[DIAG-5E0A] PSK SLOT MISMATCH: flags=0x%08x len=%u slot=0x%s host=0x%s",
             flags, length, slot_hex, host_hex);

  fpi_ssm_next_state (ssm);
}

/* No PSK reconciliation: activation goes CHECK_FW_VER -> UPLOAD_CONFIG -> TLS with the static host key (0xe4 slot reports factory bytes, 0xe0 writes rejected). */

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_RESET:
      goodix_send_reset (dev, TRUE, 20, goodixtls5xx_check_reset, ssm);
      break;

    case ACTIVATE_READ_CHIP_ID:
      goodix_send_read_sensor_register (dev, 0x0000, 4, goodixtls5xx_check_none_cmd, ssm);
      break;

    case ACTIVATE_READ_OTP:
      goodix_send_read_otp (dev, goodixtls5xx_check_none_cmd, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      goodix_send_query_firmware_version (dev, goodixtls5xx_check_firmware_version, ssm);
      break;

    case ACTIVATE_UPLOAD_CONFIG:
      goodix_send_upload_config_mcu (dev, (guint8 *) goodix_5e0a_config,
                                     sizeof (goodix_5e0a_config), NULL,
                                     goodixtls5xx_check_config_upload, ssm);
      break;

    case ACTIVATE_DIAG_READ_PSK:
      goodix_send_preset_psk_read (dev, GOODIX_5E0A_PSK_FLAGS,
                                   sizeof (goodix_5e0a_psk),
                                   diag_psk_read_cb, ssm);
      break;
    }
}

static void
on_chip_enabled (FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fp_err ("failed to enable chip: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("Chip enabled! Activation complete.");
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), NULL);
}

static void
on_tls_activation_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  /* Drop this completion if a deactivate bumped the generation while the TLS handshake was in flight. */
  if (GPOINTER_TO_UINT (user_data) != goodix_activation_gen_get (dev))
    {
      fp_dbg ("dropping stale TLS activation completion");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      fp_err ("failed during TLS activation: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  fp_dbg ("TLS connection ready! Enabling chip...");
  goodix_send_enable_chip (dev, TRUE, on_chip_enabled, NULL);
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  G_DEBUG_HERE ();
  if (!error)
    {
      /* Capture the activation generation for the staleness guard. */
      goodix_tls_init (dev, on_tls_activation_complete,
                       GUINT_TO_POINTER (goodix_activation_gen_get (dev)));
    }
  else
    {
      fp_err ("failed during activation: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
    }
}

static void
dev_activate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Invalidate any in-flight activation from a previous session. */
  goodix_activation_gen_bump (dev);

  self->session_started = FALSE;
  self->scan_ssm = NULL;
  self->down_timeout = NULL;

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

// ---- ACTIVATE SECTION END ----

// -----------------------------------------------------------------------------

// ---- SCAN SECTION START (Windows-faithful steady-state port) ----

enum goodix5e0a_scan_states {
  SCAN_5E0A_SESSION_AE,
  SCAN_5E0A_SESSION_D6,
  SCAN_5E0A_FDT_DOWN,
  SCAN_5E0A_GET_IMAGE,
  SCAN_5E0A_FDT_UP_1,
  SCAN_5E0A_UP_AE,
  SCAN_5E0A_FDT_UP_2,
  SCAN_5E0A_NUM_STATES,
};

static void
send_cmd_noreply (FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 len,
                  GoodixNoneCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixCmdCallback callback = NULL;

  if (cb)
    {
      cb_info = malloc (sizeof (GoodixCallbackInfo));
      cb_info->callback = G_CALLBACK (cb);
      cb_info->user_data = user_data;
      callback = goodix_receive_none;
    }

  goodix_send_protocol (dev, cmd, payload, len, NULL, TRUE, GOODIX_TIMEOUT,
                        FALSE, callback, cb_info);
}

static void
send_cmd_reply (FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 len,
                guint timeout_ms, GoodixDefaultCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixCmdCallback callback = NULL;

  if (cb)
    {
      cb_info = malloc (sizeof (GoodixCallbackInfo));
      cb_info->callback = G_CALLBACK (cb);
      cb_info->user_data = user_data;
      callback = goodix_receive_default;
    }

  goodix_send_protocol (dev, cmd, payload, len, NULL, TRUE, timeout_ms,
                        TRUE, callback, cb_info);
}

static void
goodix5e0a_step_cb (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_dbg ("5e0a step cb tolerant error: %s", error->message);
      g_error_free (error);
    }
  fpi_ssm_next_state (ssm);
}

static void
goodix5e0a_on_d6_reply (FpDevice *dev, guint8 *data, guint16 len,
                        gpointer ssm, GError *err)
{
  if (err)
    {
      fp_warn ("5e0a session d6 reply error: %s", err->message);
      g_error_free (err);
    }
  else
    {
      fp_dbg ("5e0a session d6 replied successfully (len=%u)", len);
    }
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  self->session_started = TRUE;
  fpi_ssm_next_state (ssm);
}

static void goodix5e0a_on_fdt_down_reply (FpDevice *dev,
                                          guint8   *data,
                                          guint16   len,
                                          gpointer  ssm,
                                          GError   *err);

static void
goodix5e0a_on_down_poll_timeout (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->down_timeout = NULL;

  FpiSsm *ssm = user_data;
  if (self->scan_ssm != ssm)
    return;

  send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN,
                  goodix_5e0a_down_s12, sizeof (goodix_5e0a_down_s12),
                  0, goodix5e0a_on_fdt_down_reply, ssm);
}

static void
goodix5e0a_on_fdt_down_reply (FpDevice *dev, guint8 *data, guint16 len,
                              gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (err)
    {
      if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  guint8 status = (len > 0) ? data[0] : 0x00;

  GString *hex_str = g_string_new ("");
  for (guint16 i = 0; i < len; i++)
    g_string_append_printf (hex_str, "%02x ", data[i]);
  fp_dbg ("5e0a D32 reply: status=0x%02x len=%u bytes=[%s]", status, len, hex_str->str);
  g_string_free (hex_str, TRUE);

  guint32 channel_energy = 0;
  if (len >= 4)
    for (guint16 i = 4; i + 1 < len; i += 2)
      channel_energy += (guint32) data[i] | ((guint32) data[i + 1] << 8);

  /* Gating rule: touch = channel-byte energy (data[2] != 0xff and channel_energy > 0), never byte0 */
  gboolean touch = (len >= 4 && data[2] != 0xff && channel_energy > 0);

  if (touch)
    {
      if (self->down_timeout)
        {
          g_source_destroy (self->down_timeout);
          self->down_timeout = NULL;
        }
      fp_dbg ("5e0a D32 touch confirmed: mask=0x%02x energy=%u",
              (data && len >= 3) ? data[2] : 0, channel_energy);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      fpi_ssm_next_state (ssm);
      return;
    }

  /* No touch (empty air or poor contact): pace re-sampling silently after 50ms */
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }
  self->down_timeout = fpi_device_add_timeout (dev, 50, goodix5e0a_on_down_poll_timeout, ssm, NULL);
}

static FpImage * process_raw_frame (GoodixTls5xxPix * pix);
static guint goodix5e0a_count_minutiae (FpImage *img);

static guint32
goodix5e0a_decode_frame (GoodixTls5xxPix *out_row_major, const guint8 *data, guint16 len)
{
  guint8 packed[GOODIX_5E0A_ACT_BYTES] = {0};
  guint32 packed_len = 0;

  if (!data)
    return 0;

  /* A canonical ChicagoH frame is 80 blocks of 132 bytes followed by a
   * four-byte footer. Each block carries 96 packed pixel bytes and 36 zero
   * padding bytes. The 80 active blocks are the natural rows of a 64x80
   * raster; keeping them in sequence avoids the destructive transpose used
   * by the superseded decoder. */
  for (guint32 block = 0; block < GOODIX_5E0A_FRAME_BLOCKS; block++)
    {
      guint32 src = block * GOODIX_5E0A_BLOCK_BYTES;
      if (src + GOODIX_5E0A_BLOCK_ACTIVE_BYTES > len)
        break;

      memcpy (packed + packed_len, data + src, GOODIX_5E0A_BLOCK_ACTIVE_BYTES);
      packed_len += GOODIX_5E0A_BLOCK_ACTIVE_BYTES;
    }

  guint32 pixel_idx = 0;
  for (guint32 i = 0; i + 6 <= packed_len && pixel_idx + 4 <= GOODIX_5E0A_FRAME_SIZE; i += 6)
    {
      const guint8 *c = packed + i;
      out_row_major[pixel_idx++] = ((c[0] & 0x0f) << 8) | c[1];
      out_row_major[pixel_idx++] = (c[3] << 4) | (c[0] >> 4);
      out_row_major[pixel_idx++] = ((c[5] & 0x0f) << 8) | c[2];
      out_row_major[pixel_idx++] = (c[4] << 4) | (c[5] >> 4);
    }

  return pixel_idx;
}

static void
goodix5e0a_on_read_img (FpDevice *dev, guint8 *data, guint16 len,
                        gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  fp_dbg ("5e0a scan_on_read_img: declen=%u", len);

  if (data && len >= 16)
    {
      fp_dbg ("5e0a raw first 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
              data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
              data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
    }

  guint32 padding_nonzero = 0;
  if (data)
    {
      for (guint32 block = 0; block < GOODIX_5E0A_FRAME_BLOCKS; block++)
        {
          guint32 pad = block * GOODIX_5E0A_BLOCK_BYTES + GOODIX_5E0A_BLOCK_ACTIVE_BYTES;
          guint32 pad_end = MIN (pad + GOODIX_5E0A_BLOCK_BYTES - GOODIX_5E0A_BLOCK_ACTIVE_BYTES,
                                 (guint32) len);
          for (guint32 i = pad; i < pad_end; i++)
            padding_nonzero += data[i] != 0;
        }
    }

  GoodixTls5xxPix *raw_frame = calloc (GOODIX_5E0A_FRAME_SIZE, sizeof (GoodixTls5xxPix));
  guint32 decoded_pixels = goodix5e0a_decode_frame (raw_frame, data, len);

  guint total_nonzero = 0;
  guint16 raw_min = 65535, raw_max = 0;
  for (guint32 i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    {
      if (raw_frame[i] > 0)
        {
          total_nonzero++;
          if (raw_frame[i] < raw_min)
            raw_min = raw_frame[i];
          if (raw_frame[i] > raw_max)
            raw_max = raw_frame[i];
        }
    }
  fp_dbg ("5e0a wire layout: decoded_px=%u blocks=%u active_bytes=%u padding_nonzero=%u footer_bytes=%u",
          decoded_pixels, MIN ((guint32) len / GOODIX_5E0A_BLOCK_BYTES,
                               (guint32) GOODIX_5E0A_FRAME_BLOCKS),
          GOODIX_5E0A_BLOCK_ACTIVE_BYTES, padding_nonzero,
          len >= GOODIX_5E0A_FRAME_WIRE_BYTES ? 4 : 0);
  fp_dbg ("5e0a row-major frame: active_px=%u nonzero=%u min=%u max=%u geometry=%dx%d (WxH)",
          decoded_pixels, total_nonzero, raw_min == 65535 ? 0 : raw_min, raw_max,
          GOODIX_5E0A_WIDTH, GOODIX_5E0A_HEIGHT);

  FpImage *img = process_raw_frame (raw_frame);

  if (img == NULL)
    {
      img = fp_image_new (GOODIX_5E0A_SCALED_WIDTH, GOODIX_5E0A_SCALED_HEIGHT);
      img->flags = FPI_IMAGE_COLORS_INVERTED;
      img->ppmm = 500.0 / 25.4;
    }

  /* [DIAG-5E0A] TEMPORARY offline-capture dump, diagnosis only, remove before merge.
   * Writes native 12-bit PGM + mindtct-input 8-bit PGM per capture to
   * /var/lib/fprint/5e0a-dump (NOT /tmp: fprintd runs with PrivateTmp, so
   * /tmp writes land in an invisible namespace). Mode 0600, biometric data.
   * Never alters the matching path: dump failures are ignored.
   * Grep DIAG-5E0A to remove. */
  {
    static guint diag_seq = 0;
    FpiDeviceAction diag_action = fpi_device_get_current_action (dev);
    const char *diag_kind = "other";
    if (diag_action == FPI_DEVICE_ACTION_ENROLL)
      diag_kind = "enroll";
    else if (diag_action == FPI_DEVICE_ACTION_VERIFY)
      diag_kind = "verify";

    g_mkdir_with_parents ("/var/lib/fprint/5e0a-dump", 0700);

    char diag_native[128], diag_scaled[128];
    g_snprintf (diag_native, sizeof (diag_native),
                "/var/lib/fprint/5e0a-dump/cap-%03u-%s-native.pgm", diag_seq, diag_kind);
    g_snprintf (diag_scaled, sizeof (diag_scaled),
                "/var/lib/fprint/5e0a-dump/cap-%03u-%s-scaled.pgm", diag_seq, diag_kind);

    FILE *dnf = fopen (diag_native, "w");
    if (dnf)
      {
        fprintf (dnf, "P2\n64 80\n4095\n");
        for (guint32 di = 0; di < GOODIX_5E0A_FRAME_SIZE; di++)
          fprintf (dnf, "%u%c", raw_frame[di], (di + 1) % 64 == 0 ? '\n' : ' ');
        fclose (dnf);
        g_chmod (diag_native, 0600);
      }

    FILE *dsf = fopen (diag_scaled, "wb");
    if (dsf)
      {
        fprintf (dsf, "P5\n128 160\n255\n");
        for (int di = 0; di < GOODIX_5E0A_SCALED_WIDTH * GOODIX_5E0A_SCALED_HEIGHT; di++)
          fputc (255 - img->data[di], dsf);
        fclose (dsf);
        g_chmod (diag_scaled, 0600);
      }

    fp_dbg ("[DIAG-5E0A] dumped cap-%03u kind=%s declen=%u minutiae=%u",
            diag_seq, diag_kind, len, goodix5e0a_count_minutiae (img));
    diag_seq++;
  }

  free (raw_frame);

  FpiDeviceAction action = fpi_device_get_current_action (dev);
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      guint minutiae_count = goodix5e0a_count_minutiae (img);
      fp_dbg ("5e0a enrollment quality check: minutiae_count=%u (floor=%d)",
              minutiae_count, GOODIX_5E0A_ENROLL_MIN_MINUTIAE);
      if (minutiae_count < GOODIX_5E0A_ENROLL_MIN_MINUTIAE)
        {
          fp_dbg ("5e0a enrollment touch rejected: minutiae_count=%u < %d (press firmer)",
                  minutiae_count, GOODIX_5E0A_ENROLL_MIN_MINUTIAE);
          g_object_unref (img);
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (dev), FP_DEVICE_RETRY_TOO_SHORT);
          fpi_ssm_next_state (ssm);
          return;
        }
    }

  /* Verify passthrough: report capture immediately so auth finishes without waiting for finger-lift polls. */
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev), img);

  if (action != FPI_DEVICE_ACTION_ENROLL)
    {
      self->scan_ssm = NULL;
      fpi_ssm_mark_completed (ssm);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
    }
  else
    {
      fpi_ssm_next_state (ssm);
    }
}

static void
goodix5e0a_on_fdt_up_reply (FpDevice *dev, guint8 *data, guint16 len,
                            gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (err)
    {
      fp_dbg ("5e0a D34 reply (tolerant): %s", err->message);
      g_error_free (err);
    }
  else
    {
      fp_dbg ("5e0a D34 finger release reply: len=%u", len);
    }

  /* Mark current scan SSM completed before notifying libfprint,
   * so that when libfprint synchronously requests AWAIT_FINGER_ON,
   * the concurrency guard does not block the new scan SSM. */
  self->scan_ssm = NULL;
  fpi_ssm_next_state (ssm);
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
}

static void
goodix5e0a_scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_5E0A_SESSION_AE:
      send_cmd_noreply (dev, GOODIX_CMD_QUERY_MCU_STATE,
                        goodix_5e0a_query_ae, sizeof (goodix_5e0a_query_ae),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_SESSION_D6:
      if (self->session_started)
        {
          fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_DOWN);
          return;
        }
      send_cmd_reply (dev, GOODIX_CMD_SESSION_D6,
                      goodix_5e0a_session_d6, sizeof (goodix_5e0a_session_d6),
                      GOODIX_TIMEOUT, goodix5e0a_on_d6_reply, ssm);
      break;

    case SCAN_5E0A_FDT_DOWN:
      send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN,
                      goodix_5e0a_down_s12, sizeof (goodix_5e0a_down_s12),
                      0, goodix5e0a_on_fdt_down_reply, ssm);
      break;

    case SCAN_5E0A_GET_IMAGE:
      goodix_tls_read_image (dev, goodix5e0a_on_read_img, ssm);
      break;

    case SCAN_5E0A_FDT_UP_1:
      send_cmd_noreply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                        goodix_5e0a_up_u01, sizeof (goodix_5e0a_up_u01),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_UP_AE:
      send_cmd_noreply (dev, GOODIX_CMD_QUERY_MCU_STATE,
                        goodix_5e0a_query_ae, sizeof (goodix_5e0a_query_ae),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_FDT_UP_2:
      send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                      goodix_5e0a_up_u01, sizeof (goodix_5e0a_up_u01),
                      5000, goodix5e0a_on_fdt_up_reply, ssm);
      break;
    }
}

static void
goodix5e0a_scan_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->scan_ssm = NULL;
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }

  if (error)
    {
      fp_err ("5e0a failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("5e0a finished scan stage");
}

static void
goodix5e0a_scan_start (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (self->scan_ssm != NULL)
    {
      fp_dbg ("5e0a scan SSM already active, ignoring start request");
      return;
    }

  self->scan_ssm = fpi_ssm_new (dev, goodix5e0a_scan_run_state, SCAN_5E0A_NUM_STATES);
  fpi_ssm_start (self->scan_ssm, goodix5e0a_scan_complete);
}

static void
goodix5e0a_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    goodix5e0a_scan_start (FP_DEVICE (img_dev));
}

static void
goodix5e0a_deactivate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Orphan any in-flight TLS activation; its completion will drop. */
  goodix_activation_gen_bump (dev);

  self->session_started = FALSE;
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }

  goodix_reset_state (dev);
  if (self->scan_ssm != NULL)
    {
      fpi_ssm_free (self->scan_ssm);
      self->scan_ssm = NULL;
    }

  GError *tls_err = NULL;
  goodix_shutdown_tls (dev, &tls_err);
  goodix_stop_read_loop (dev);
  fpi_image_device_deactivate_complete (img_dev, tls_err);
}

// ---- SCAN SECTION END ----

static void
fpi_device_goodixtls5e0a_init (FpiDeviceGoodixTls5e0a *self)
{
  self->session_started = FALSE;
  self->scan_ssm = NULL;
  self->down_timeout = NULL;
}

static double
goodix5e0a_axis_correlation (const GoodixTls5xxPix *pix,
                             int                    width,
                             int                    height,
                             int                    dx,
                             int                    dy)
{
  double sum_a = 0.0, sum_b = 0.0;
  guint count = 0;

  for (int y = 0; y + dy < height; y++)
    for (int x = 0; x + dx < width; x++)
      {
        sum_a += pix[y * width + x];
        sum_b += pix[(y + dy) * width + x + dx];
        count++;
      }

  if (count == 0)
    return 0.0;

  double mean_a = sum_a / count;
  double mean_b = sum_b / count;
  double covariance = 0.0, variance_a = 0.0, variance_b = 0.0;

  for (int y = 0; y + dy < height; y++)
    for (int x = 0; x + dx < width; x++)
      {
        double a = pix[y * width + x] - mean_a;
        double b = pix[(y + dy) * width + x + dx] - mean_b;
        covariance += a * b;
        variance_a += a * a;
        variance_b += b * b;
      }

  double denominator = sqrt (variance_a * variance_b);
  return denominator > 1e-6 ? covariance / denominator : 0.0;
}

static FpImage *
process_raw_frame (GoodixTls5xxPix * pix)
{
  const int W = GOODIX_5E0A_WIDTH;
  const int H = GOODIX_5E0A_HEIGHT;
  const int dst_w = GOODIX_5E0A_SCALED_WIDTH;
  const int dst_h = GOODIX_5E0A_SCALED_HEIGHT;

  guint16 min_v = 65535, max_v = 0;
  guint active = 0;

  for (int r = 0; r < H; ++r)
    {
      for (int c = 0; c < W; ++c)
        {
          guint16 v = pix[r * W + c];
          if (v > 30)
            {
              active++;
              if (v < min_v)
                min_v = v;
              if (v > max_v)
                max_v = v;
            }
        }
    }

  if (min_v == 65535)
    min_v = 0;
  guint16 range = (max_v > min_v) ? (max_v - min_v) : 1;

  double horizontal_corr = goodix5e0a_axis_correlation (pix, W, H, 1, 0);
  double vertical_corr = goodix5e0a_axis_correlation (pix, W, H, 0, 1);
  double horizontal_lag4_corr = goodix5e0a_axis_correlation (pix, W, H, 4, 0);

  GString *active_cols = g_string_new ("");
  for (int c = 0; c < W; ++c)
    {
      guint32 c_sum = 0;
      for (int r = 0; r < H; ++r)
        c_sum += pix[r * W + c];
      if (c_sum > 0)
        g_string_append_printf (active_cols, "%d ", c);
    }
  if (active_cols->len > 0)
    fp_dbg ("5e0a active cols: %s", active_cols->str);
  else
    fp_dbg ("5e0a active cols: NONE (all 0)");
  g_string_free (active_cols, TRUE);

  fp_dbg ("5e0a frame stats: active=%u, min_v=%u, max_v=%u, range=%u, h_corr=%.3f, v_corr=%.3f, h_lag4_corr=%.3f (native %dx%d WxH)",
          active, min_v, max_v, range,
          horizontal_corr, vertical_corr, horizontal_lag4_corr, W, H);

  if (active < 64 || range < 8)
    return NULL;

  /* Remove the slowly varying pressure/offset field before global scaling.
   * A 3x3 local mean is the smallest window that removes this field without
   * averaging across a full ridge period. */
  float residual[GOODIX_5E0A_FRAME_SIZE];
  float residual_min = G_MAXFLOAT;
  float residual_max = -G_MAXFLOAT;
  for (int y = 0; y < H; y++)
    {
      for (int x = 0; x < W; x++)
        {
          guint32 local_sum = 0;
          guint local_count = 0;
          for (int yy = MAX (0, y - 1); yy <= MIN (H - 1, y + 1); yy++)
            for (int xx = MAX (0, x - 1); xx <= MIN (W - 1, x + 1); xx++)
              {
                local_sum += pix[yy * W + xx];
                local_count++;
              }

          float value = pix[y * W + x] - (float) local_sum / local_count;
          residual[y * W + x] = value;
          residual_min = MIN (residual_min, value);
          residual_max = MAX (residual_max, value);
        }
    }

  float residual_range = residual_max - residual_min;
  fp_dbg ("5e0a local contrast: min=%.2f max=%.2f range=%.2f window=3x3 gain=%.2f",
          residual_min, residual_max, residual_range, GOODIX_5E0A_CONTRAST_GAIN);
  if (residual_range < 1.0f)
    return NULL;

  guint8 normalized[GOODIX_5E0A_FRAME_SIZE];
  for (guint i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    {
      int value = (int) roundf (128.0f + residual[i] * GOODIX_5E0A_CONTRAST_GAIN);
      normalized[i] = (guint8) CLAMP (value, 0, 255);
    }

  /* Create the scaled 128x160 image directly via bilinear upscaling.
   * Use FPI_IMAGE_COLORS_INVERTED for capacitive ridges (high ADC = black).
   * Omit FPI_IMAGE_PARTIAL so remove_perimeter_pts=0 retains edge minutiae. */
  FpImage *scaled = fp_image_new (dst_w, dst_h);
  scaled->flags = FPI_IMAGE_COLORS_INVERTED;
  scaled->ppmm = 500.0 / 25.4;

  for (int y = 0; y < dst_h; y++)
    {
      float src_y = (y + 0.5f) * 0.5f - 0.5f;
      if (src_y < 0.0f)
        src_y = 0.0f;
      int y0 = (int) src_y;
      int y1 = (y0 + 1 < H) ? y0 + 1 : y0;
      float y_frac = src_y - (float) y0;

      for (int x = 0; x < dst_w; x++)
        {
          float src_x = (x + 0.5f) * 0.5f - 0.5f;
          if (src_x < 0.0f)
            src_x = 0.0f;
          int x0 = (int) src_x;
          int x1 = (x0 + 1 < W) ? x0 + 1 : x0;
          float x_frac = src_x - (float) x0;

          float top = (float) normalized[y0 * W + x0] * (1.0f - x_frac) + (float) normalized[y0 * W + x1] * x_frac;
          float bot = (float) normalized[y1 * W + x0] * (1.0f - x_frac) + (float) normalized[y1 * W + x1] * x_frac;
          float val = top * (1.0f - y_frac) + bot * y_frac;
          int norm = (int) roundf (val);
          scaled->data[y * dst_w + x] = (guint8) CLAMP (norm, 0, 255);
        }
    }

  fp_dbg ("5e0a scaled image: %dx%d (WxH) flags=0x%02x active=%u range=%u ppmm=%.3f",
          scaled->width, scaled->height, scaled->flags, active, range, scaled->ppmm);
  return scaled;
}

static guint
goodix5e0a_count_minutiae (FpImage *img)
{
  if (!img || !img->data)
    return 0;

  int w = img->width;
  int h = img->height;
  unsigned char *buf = g_memdup2 (img->data, w * h);

  if (img->flags & FPI_IMAGE_COLORS_INVERTED)
    for (int i = 0; i < w * h; i++)
      buf[i] = 255 - buf[i];

  LFSPARMS parms = g_lfsparms_V2;
  parms.remove_perimeter_pts = 0;
  double ppmm = img->ppmm > 0 ? img->ppmm : (500.0 / 25.4);

  MINUTIAE *minutiae = NULL;
  int *qmap = NULL, *dmap = NULL, *lcmap = NULL, *lfmap = NULL, *hcmap = NULL;
  int mw, mh, bw, bh, bd;
  unsigned char *bdata = NULL;

  int ret = get_minutiae (&minutiae, &qmap, &dmap, &lcmap, &lfmap, &hcmap,
                          &mw, &mh, &bdata, &bw, &bh, &bd,
                          buf, w, h, 8, ppmm, &parms);
  guint count = (ret == 0 && minutiae) ? minutiae->num : 0;

  g_free (buf);
  if (minutiae)
    free_minutiae (minutiae);
  if (qmap)
    g_free (qmap);
  if (dmap)
    g_free (dmap);
  if (lcmap)
    g_free (lcmap);
  if (lfmap)
    g_free (lfmap);
  if (hcmap)
    g_free (hcmap);
  if (bdata)
    g_free (bdata);

  return count;
}

void
goodix5e0a_suspend (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  fp_dbg ("5e0a suspend requested during action: %d", action);

  /* Orphan any in-flight TLS handshake/activation; its completion will drop. */
  goodix_activation_gen_bump (dev);

  self->session_started = FALSE;
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }

  /* Reset in-flight protocol commands and timeout */
  goodix_reset_state (dev);

  /* Free in-flight scan state machine */
  if (self->scan_ssm != NULL)
    {
      fpi_ssm_free (self->scan_ssm);
      self->scan_ssm = NULL;
    }

  /* Terminate background read loop and cancel transfers */
  goodix_stop_read_loop (dev);

  /* Tear down TLS context */
  goodix_shutdown_tls (dev, NULL);

  /* Complete suspend with NOT_SUPPORTED to trigger clean core deactivation
   * of the interactive task, releasing PAM claims before sleep. */
  fpi_device_suspend_complete (dev, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
}

void
goodix5e0a_resume (FpDevice *dev)
{
  fp_dbg ("5e0a resume requested");

  /* Device state was cleaned up during suspend; complete resume immediately.
   * Subsequent user claims will trigger clean open/activate and hardware re-priming. */
  fpi_device_resume_complete (dev, NULL);
}

static void
fpi_device_goodixtls5e0a_class_init (FpiDeviceGoodixTls5e0aClass * class)
{
  FpiDeviceGoodixTlsClass * gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass * dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass * img_dev_class = FP_IMAGE_DEVICE_CLASS (class);
  FpiDeviceGoodixTls5xxClass * xx_cls = FPI_DEVICE_GOODIXTLS5XX_CLASS (class);

  xx_cls->process_raw_frame = process_raw_frame;
  xx_cls->scan_height = GOODIX_5E0A_HEIGHT;
  xx_cls->scan_width = GOODIX_5E0A_WIDTH;
  xx_cls->psk = goodix_5e0a_psk;
  xx_cls->psk_flags = GOODIX_5E0A_PSK_FLAGS;
  xx_cls->psk_len = sizeof (goodix_5e0a_psk);
  xx_cls->firmware_version = GOODIX_5E0A_FIRMWARE_VERSION;
  xx_cls->reset_number = GOODIX_5E0A_RESET_NUMBER;
  xx_cls->has_calibration = FALSE;

  gx_class->interface = GOODIX_5E0A_INTERFACE;
  gx_class->ep_in = GOODIX_5E0A_EP_IN;
  gx_class->ep_out = GOODIX_5E0A_EP_OUT;

  dev_class->id = "goodixtls5e0a";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 5e0a";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = goodix_5e0a_id_table;
  dev_class->nr_enroll_stages = 12;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1; // Disable thermal watchdog
  dev_class->suspend = goodix5e0a_suspend;
  dev_class->resume = goodix5e0a_resume;

  img_dev_class->activate = dev_activate;
  img_dev_class->change_state = goodix5e0a_change_state;
  img_dev_class->deactivate = goodix5e0a_deactivate;
  img_dev_class->bz3_threshold = 12;
  img_dev_class->img_width = GOODIX_5E0A_SCALED_WIDTH;
  img_dev_class->img_height = GOODIX_5E0A_SCALED_HEIGHT;

  fpi_device_class_auto_initialize_features (dev_class);
}
