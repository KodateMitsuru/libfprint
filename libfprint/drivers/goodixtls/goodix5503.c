// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Alireza S.N. <alireza6677@gmail.com>

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

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
#define FP_COMPONENT "goodixtls5503"

#include <glib.h>
#include <math.h>
#include <string.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix5503.h"
#include "goodix_proto.h"

#define GOODIX5503_WIDTH 64
#define GOODIX5503_HEIGHT 80
#define GOODIX5503_SCAN_WIDTH 64
#define GOODIX5503_FRAME_SIZE (GOODIX5503_WIDTH * GOODIX5503_HEIGHT)
// For every 4 pixels there are 6 bytes and there are 8 extra start bytes and 5
// extra end
#define GOODIX5503_RAW_FRAME_SIZE \
  (GOODIX5503_HEIGHT * GOODIX5503_SCAN_WIDTH) / 4 * 6
#define GOODIX5503_CAP_FRAMES 1  // Number of frames we capture per swipe

typedef unsigned short Goodix5503Pix;

struct _FpiDeviceGoodixTls5503 {
  FpiDeviceGoodixTls parent;

  guint8 *otp;

  GSList *frames;

  Goodix5503Pix empty_img[GOODIX5503_FRAME_SIZE];
};

G_DECLARE_FINAL_TYPE(FpiDeviceGoodixTls5503, fpi_device_goodixtls5503, FPI,
                     DEVICE_GOODIXTLS5503, FpiDeviceGoodixTls);

G_DEFINE_TYPE(FpiDeviceGoodixTls5503, fpi_device_goodixtls5503,
              FPI_TYPE_DEVICE_GOODIXTLS);
// ---- ACTIVE SECTION START ----

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_ENABLE_CHIP,
  ACTIVATE_NOP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_RESET,
  ACTIVATE_SET_MCU_IDLE,
  ACTIVATE_SET_MCU_CONFIG,
  ACTIVATE_NUM_STATES,
};

static void check_none(FpDevice *dev, gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fpi_ssm_next_state(user_data);
}

static void check_firmware_version(FpDevice *dev, gchar *firmware,
                                   gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fp_dbg("Device firmware: \"%s\"", firmware);
  g_print("%s\n", firmware);

  if (!(strcmp(firmware, GOODIX_5503_FIRMWARE_VERSION) ||
        strcmp(firmware, GOODIX_5503_FIRMWARE_VERSION2))) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                "Invalid device firmware: \"%s\"", firmware);
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fpi_ssm_next_state(user_data);
}

static void check_reset(FpDevice *dev, gboolean success, guint16 number,
                        gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  if (!success) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to reset device");
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fp_dbg("Device reset number: %d", number);

  if (number != GOODIX_5503_RESET_NUMBER) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                "Invalid device reset number: %d", number);
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fpi_ssm_next_state(user_data);
}

static void check_preset_psk_read(FpDevice *dev, gboolean success,
                                  guint32 flags, guint8 *psk, guint16 length,
                                  gpointer user_data, GError *error) {
  g_autofree gchar *psk_str = data_to_str(psk, length);

  if (error) {
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  if (!success) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to read PSK from device");
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fp_dbg("Device PSK: 0x%s", psk_str);
  fp_dbg("Device PSK flags: 0x%08x", flags);

  if (flags != GOODIX_5503_PSK_FLAGS) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                "Invalid device PSK flags: 0x%08x", flags);
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  if (length != sizeof(goodix_5503_psk_0)) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                "Invalid device PSK: 0x%s", psk_str);
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  if (memcmp(psk, goodix_5503_psk_0, sizeof(goodix_5503_psk_0))) {
    g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                "Invalid device PSK: 0x%s", psk_str);
    fpi_ssm_mark_failed(user_data, error);
    return;
  }

  fpi_ssm_next_state(user_data);
}
static void check_idle(FpDevice *dev, gpointer user_data, GError *err) {
  if (err) {
    fpi_ssm_mark_failed(user_data, err);
    return;
  }
  fpi_ssm_next_state(user_data);
}
static void check_config_upload(FpDevice *dev, gboolean success,
                                gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
  } else if (!success) {
    fpi_ssm_mark_failed(user_data,
                        g_error_new(FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                    "failed to upload mcu config"));
  } else {
    fpi_ssm_next_state(user_data);
  }
}
static void check_powerdown_scan_freq(FpDevice *dev, gboolean success,
                                      gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
  } else if (!success) {
    fpi_ssm_mark_failed(user_data,
                        g_error_new(FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                    "failed to set powerdown freq"));
  } else {
    // goodix_send_mcu_get_pov_image(dev, check_mcu_pov_image, user_data);
  }
}

static void check_mcu_pov_image(FpDevice *dev, gboolean success,
                                gpointer user_data, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(user_data, error);
  } else if (!success) {
    fpi_ssm_mark_failed(user_data,
                        g_error_new(FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                    "failed to set powerdown freq"));
  } else {
    fpi_ssm_next_state(user_data);
  }
}

static void activate_run_state(FpiSsm *ssm, FpDevice *dev) {
  switch (fpi_ssm_get_cur_state(ssm)) {
    case ACTIVATE_READ_AND_NOP:
      g_print("Read and NO OP\n");
      // Nop seems to clear the previous command buffer. But we are
      // unable to do so.
      goodix_start_read_loop(dev);
      goodix_send_nop(dev, check_none, ssm);
      break;

    case ACTIVATE_ENABLE_CHIP:
      g_print("Enable Chip\n");
      goodix_send_enable_chip(dev, TRUE, check_none, ssm);
      break;

    case ACTIVATE_NOP:
      g_print("NO OP\n");
      goodix_send_nop(dev, check_none, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      g_print("Checking FW\n");
      goodix_send_firmware_version(dev, check_firmware_version, ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      g_print("Checking PSK\n");
      goodix_send_preset_psk_read(dev, GOODIX_5503_PSK_FLAGS, 32,
                                  check_preset_psk_read, ssm);
      break;

    case ACTIVATE_RESET:
      g_print("Reset Device\n");
      goodix_send_reset(dev, TRUE, 20, check_reset, ssm);
      break;

    case ACTIVATE_SET_MCU_IDLE:
      g_print("Device IDLE\n");
      goodix_send_mcu_switch_to_idle_mode(dev, 20, check_idle, ssm);
      break;

      // case ACTIVATE_SET_ODP:
      //     goodix_send_read_otp(dev, read_otp_callback, ssm);
      //     break;

    case ACTIVATE_SET_MCU_CONFIG:
      g_print("Uploading Device Config\n");
      goodix_send_upload_config_mcu(dev, goodix_5503_config,
                                    sizeof(goodix_5503_config), NULL,
                                    check_config_upload, ssm);
      break;

      // case ACTIVATE_SET_POWERDOWN_SCAN_FREQUENCY:
      //     g_print("Powerdown Scan Freq\n");
      //     /*goodix_send_set_powerdown_scan_frequency(
      //         dev, 100, check_powerdown_scan_freq, ssm);*/
      //     //goodix_send_drv_state(dev, check_powerdown_scan_freq, ssm);
      //     fpi_ssm_next_state(ssm);
      //     break;
  }
}

static void tls_activation_complete(FpDevice *dev, gpointer user_data,
                                    GError *error) {
  if (error) {
    fp_err("failed to complete tls activation: %s", error->message);
    return;
  }
  FpImageDevice *image_dev = FP_IMAGE_DEVICE(dev);

  fpi_image_device_activate_complete(image_dev, error);
}

static void activate_complete(FpiSsm *ssm, FpDevice *dev, GError *error) {
  G_DEBUG_HERE();
  if (!error)
    goodix_tls(dev, tls_activation_complete, NULL);
  else {
    fp_err("failed during activation: %s (code: %d)", error->message,
           error->code);
    fpi_image_device_activate_complete(FP_IMAGE_DEVICE(dev), error);
  }
}

// ---- ACTIVE SECTION END ----

// -----------------------------------------------------------------------------

// ---- SCAN SECTION START ----

enum SCAN_STAGES {
  SCAN_STAGE_RESET_SCANNER,
  SCAN_STAGE_QUERY_MCU,
  SCAN_STAGE_SWITCH_TO_FDT_DOWN,
  SCAN_STAGE_GET_IMG,
  SCAN_STAGE_RESET_SCANNER2,
  SCAN_STAGE_SWITCH_TO_FDT_UP_NO_REPLY,
  SCAN_STAGE_SWITCH_TO_FDT_UP,
  SCAN_STAGE_SWITCH_TO_FDT_DOWN_NO_REPLY,
  SCAN_STAGE_QUERY_MCU_TURN_OFF_LIGHT,
  SCAN_STAGE_SWITCH_TO_IDLE_MODE,
  SCAN_STAGE_SWITCH_TO_SLEEP_MODE,
  SCAN_STAGE_SWITCH_TO_FDT_DONE,
  SCAN_STAGE_NUM,
};

static void check_none_cmd(FpDevice *dev, guint8 *data, guint16 len,
                           gpointer ssm, GError *err) {
  if (err) {
    g_print("CHECK NONE FAILED\n");
    fpi_ssm_mark_failed(ssm, err);
    return;
  }
  g_print("CHECK NONE SUCCESS\n");
  fpi_ssm_next_state(ssm);
}

static unsigned char get_pix(struct fpi_frame_asmbl_ctx *ctx,
                             struct fpi_frame *frame, unsigned int x,
                             unsigned int y) {
  return frame->data[x + y * GOODIX5503_WIDTH];
}

// Bitdepth is 12, but we have to fit it in a byte
static unsigned char squash(int v) { return v / 16; }

static void decode_frame(Goodix5503Pix frame[GOODIX5503_FRAME_SIZE],
                         const guint8 *raw_frame) {
  Goodix5503Pix uncropped[GOODIX5503_SCAN_WIDTH * GOODIX5503_HEIGHT];
  Goodix5503Pix *pix = uncropped;
  for (int i = 0; i < GOODIX5503_RAW_FRAME_SIZE; i += 6) {
    const guint8 *chunk = raw_frame + i;
    *pix++ = ((chunk[0] & 0xf) << 8) + chunk[1];
    *pix++ = (chunk[3] << 4) + (chunk[0] >> 4);
    *pix++ = ((chunk[5] & 0xf) << 8) + chunk[2];
    *pix++ = (chunk[4] << 4) + (chunk[5] >> 4);
  }

  for (int y = 0; y != GOODIX5503_HEIGHT; ++y) {
    for (int x = 0; x != GOODIX5503_WIDTH; ++x) {
      const int idx = x + y * GOODIX5503_SCAN_WIDTH;
      frame[x + y * GOODIX5503_WIDTH] = uncropped[idx];
    }
  }
}
static int goodix_cmp_short(const void *a, const void *b) {
  return (int)(*(short *)a - *(short *)b);
}

static void rotate_frame(Goodix5503Pix frame[GOODIX5503_FRAME_SIZE]) {
  Goodix5503Pix buff[GOODIX5503_FRAME_SIZE];

  for (int y = 0; y != GOODIX5503_HEIGHT; ++y) {
    for (int x = 0; x != GOODIX5503_WIDTH; ++x) {
      buff[x * GOODIX5503_WIDTH + y] = frame[x + y * GOODIX5503_WIDTH];
    }
  }
  memcpy(frame, buff, GOODIX5503_FRAME_SIZE);
}
static void squash_frame(Goodix5503Pix *frame, guint8 *squashed) {
  for (int i = 0; i != GOODIX5503_FRAME_SIZE; ++i) {
    squashed[i] = squash(frame[i]);
  }
}
/**
 * @brief Squashes the 12 bit pixels of a raw frame into the 4 bit pixels used
 * by libfprint.
 * @details Borrowed from the elan driver. We reduce frames to
 * within the max and min.
 *
 * @param frame
 * @param squashed
 */
static void squash_frame_linear(Goodix5503Pix *frame, guint8 *squashed) {
  Goodix5503Pix min = 0xffff;
  Goodix5503Pix max = 0;

  for (int i = 0; i != GOODIX5503_FRAME_SIZE; ++i) {
    const Goodix5503Pix pix = frame[i];
    if (pix < min) {
      min = pix;
    }
    if (pix > max) {
      max = pix;
    }
  }

  for (int i = 0; i != GOODIX5503_FRAME_SIZE; ++i) {
    const Goodix5503Pix pix = frame[i];
    if (pix - min == 0 || max - min == 0) {
      squashed[i] = 0;
    } else {
      squashed[i] = (pix - min) * 0xff / (max - min);
    }
  }
}

/**
 * @brief Subtracts the background from the frame
 *
 * @param frame
 * @param background
 */
static gboolean postprocess_frame(
    Goodix5503Pix frame[GOODIX5503_FRAME_SIZE],
    Goodix5503Pix background[GOODIX5503_FRAME_SIZE]) {
  int sum = 0;
  for (int i = 0; i != GOODIX5503_FRAME_SIZE; ++i) {
    Goodix5503Pix *og_px = frame + i;
    Goodix5503Pix bg_px = background[i];
    if (bg_px > *og_px) {
      *og_px = bg_px - *og_px;
    } else {
      *og_px -= bg_px;
    }

    sum += *og_px;
  }
  if (sum == 0) {
    fp_warn(
        "frame darker than background, finger on scanner during "
        "calibration?");
  }
  return sum != 0;
}

typedef struct _frame_processing_info {
  FpiDeviceGoodixTls5503 *dev;
  GSList **frames;

} frame_processing_info;

static void process_frame(Goodix5503Pix *raw_frame,
                          frame_processing_info *info) {
  struct fpi_frame *frame =
      g_malloc(GOODIX5503_FRAME_SIZE + sizeof(struct fpi_frame));
  postprocess_frame(raw_frame, info->dev->empty_img);
  squash_frame_linear(raw_frame, frame->data);

  *(info->frames) = g_slist_append(*(info->frames), frame);
}

static void save_frame(FpiDeviceGoodixTls5503 *self, guint8 *raw) {
  Goodix5503Pix *frame = malloc(GOODIX5503_FRAME_SIZE * sizeof(Goodix5503Pix));
  decode_frame(frame, raw);
  self->frames = g_slist_append(self->frames, frame);
}

static void scan_on_read_img(FpDevice *dev, guint8 *data, guint16 len,
                             gpointer ssm, GError *err) {
  g_print("SCAN_ON_READ_IMG\n");
  if (err) {
    fpi_ssm_mark_failed(ssm, err);
    return;
  }

  FpiDeviceGoodixTls5503 *self = FPI_DEVICE_GOODIXTLS5503(dev);
  save_frame(self, data);
  if (g_slist_length(self->frames) <= GOODIX5503_CAP_FRAMES) {
    fpi_ssm_jump_to_state(ssm, SCAN_STAGE_RESET_SCANNER);
  } else {
    GSList *raw_frames = g_slist_nth(self->frames, 1);

    FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);
    struct fpi_frame_asmbl_ctx assembly_ctx;
    assembly_ctx.frame_width = GOODIX5503_WIDTH;
    assembly_ctx.frame_height = GOODIX5503_HEIGHT;
    assembly_ctx.image_width = GOODIX5503_WIDTH * 1;
    assembly_ctx.get_pixel = get_pix;

    GSList *frames = NULL;
    frame_processing_info pinfo = {.dev = self, .frames = &frames};

    g_slist_foreach(raw_frames, (GFunc)process_frame, &pinfo);
    frames = g_slist_reverse(frames);

    g_print("\n");
    fpi_do_movement_estimation(&assembly_ctx, frames);
    g_print("MOVEMENT EST DOOONEE\n");
    FpImage *img = fpi_assemble_frames(&assembly_ctx, frames);

    g_slist_free_full(frames, g_free);
    g_slist_free_full(self->frames, g_free);
    self->frames = g_slist_alloc();

    g_print("Signal IMG Capture\n");
    fpi_image_device_image_captured(img_dev, img);
    // save_image_to_pgm(img, "/tmp/captured.pgm");

    g_print("Next State\n");
    fpi_ssm_next_state(ssm);
  }
}

gboolean save_image_to_pgm2(guchar *data, const char *path) {
  FILE *fd = fopen(path, "w");
  size_t write_size = 7656;
  int r;

  if (!fd) {
    g_warning("could not open '%s' for writing: %d", path, errno);
    return FALSE;
  }

  r = fprintf(fd, "P2\n%d %d\n255\n", GOODIX5503_WIDTH, GOODIX5503_HEIGHT);
  if (r < 0) {
    fclose(fd);
    g_critical("pgm header write failed, error %d", r);
    return FALSE;
  }

  for (int i = 0; i < write_size; i += 1) {
    r = fprintf(fd, "%d\n", data[i]);
  }
  fclose(fd);
  g_debug("written to '%s'", path);

  return TRUE;
}

gboolean save_image_to_pgm(FpImage *img, const char *path) {
  FILE *fd = fopen(path, "w");
  size_t write_size;
  const guchar *data = fp_image_get_data(img, &write_size);
  int r;

  if (!fd) {
    g_warning("could not open '%s' for writing: %d", path, errno);
    return FALSE;
  }

  r = fprintf(fd, "P5 %d %d 255\n", fp_image_get_width(img),
              fp_image_get_height(img));
  if (r < 0) {
    fclose(fd);
    g_critical("pgm header write failed, error %d", r);
    return FALSE;
  }

  r = fwrite(data, 1, write_size, fd);
  if (r < write_size) {
    fclose(fd);
    g_critical("short write (%d)", r);
    return FALSE;
  }

  fclose(fd);
  g_debug("written to '%s'", path);

  return TRUE;
}

enum scan_empty_img_state {
  SCAN_EMPTY_GET_IMG,

  SCAN_EMPTY_NUM,
};

static void on_scan_empty_img(FpDevice *dev, guint8 *data, guint16 length,
                              gpointer ssm, GError *error) {
  if (error) {
    fpi_ssm_mark_failed(ssm, error);
    return;
  }
  FpiDeviceGoodixTls5503 *self = FPI_DEVICE_GOODIXTLS5503(dev);
  decode_frame(self->empty_img, data);
  // FpImage *bgk = fp_image_new(GOODIX5503_WIDTH, GOODIX5503_HEIGHT);
  // squash_frame(self->empty_img, bgk->data);
  // save_image_to_pgm(bgk, "./background.pgm");
  fpi_ssm_next_state(ssm);
}
static void scan_empty_run(FpiSsm *ssm, FpDevice *dev) {
  switch (fpi_ssm_get_cur_state(ssm)) {
    case SCAN_EMPTY_GET_IMG:
      goodix_tls_read_image(dev, on_scan_empty_img, ssm);
      break;
  }
}

static void scan_empty_img(FpDevice *dev, FpiSsm *ssm) {
  fpi_ssm_start_subsm(ssm, fpi_ssm_new(dev, scan_empty_run, SCAN_EMPTY_NUM));
}

static void scan_get_img(FpDevice *dev, FpiSsm *ssm) {
  goodix_tls_read_image(dev, scan_on_read_img, ssm);
}

const guint8 fdt_switch_state_mode_5503[] = {
    0x0d, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0x96, 0x80, 0x91, 0x80, 0x92, 0x80, 0x85, 0x80, 0x8c, 0x80, 0x86};

const guint8 fdt_switch_state_mode2_5503[] = {
    0x0d, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0xb9, 0x80, 0xae, 0x80, 0xb9, 0x80, 0xaf, 0x80, 0xb5, 0x80, 0xaa};

const guint8 fdt_switch_state_down_5503[] = {
    0x0c, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0xb9, 0x80, 0xae, 0x80, 0xb9, 0x80, 0xaf, 0x80, 0xb5, 0x80, 0xaa};

const guint8 fdt_switch_state_down2_5503[] = {
    0x0c, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0xba, 0x80, 0xaf, 0x80, 0xba, 0x80, 0xb0, 0x80, 0xb6, 0x80, 0xab};

const guint8 fdt_switch_state_up_5503[] = {
    0x0e, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0x95, 0x80, 0x89, 0x80, 0x99, 0x80, 0x8a, 0x80, 0x8d, 0x80, 0x8d};

const guint8 fdt_switch_state_up2_5503[] = {
    0x0e, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00, 0x80,
    0x9b, 0x80, 0x8e, 0x80, 0xa2, 0x80, 0x90, 0x80, 0x9f, 0x80, 0xa8};

static void receive_fdt_down_ack(FpDevice *dev, guint8 *data, guint16 len,
                                 gpointer ssm, GError *err) {
  if (err) {
    fpi_ssm_mark_failed(ssm, err);
    return;
  }

  // Second FDT down must send a response
  goodix_send_mcu_switch_to_fdt_down(dev, (guint8 *)fdt_switch_state_down_5503,
                                     sizeof(fdt_switch_state_down_5503), NULL,
                                     check_none_cmd, ssm);
}
static void write_sensor_complete(FpDevice *dev, gpointer user_data,
                                  GError *error) {
  if (error) {
    fp_err("failed to scan: %s (code: %d)", error->message, error->code);
    return;
  }
  scan_get_img(dev, user_data);
}
static void scan_run_state(FpiSsm *ssm, FpDevice *dev) {
  FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);
  GoodixQueryMcuState payload;
  switch (fpi_ssm_get_cur_state(ssm)) {
    case SCAN_STAGE_RESET_SCANNER:
      g_print("RESET SCANNER\n");
      goodix_send_mcu_switch_to_fdt_mode(
          dev, (guint8 *)fdt_switch_state_mode_5503,
          sizeof(fdt_switch_state_mode_5503), NULL, check_none_cmd, ssm);
      break;
    case SCAN_STAGE_QUERY_MCU:
      g_print("QUERY MCU\n");
      payload.unused_flags = 0x00;
      goodix_send_query_mcu_state(dev, (guint8 *)&payload, sizeof(payload),
                                  check_none_cmd, ssm);
      break;

    case SCAN_STAGE_SWITCH_TO_FDT_DOWN:
      g_print("SWITCH TO FDT DOWN\n");
      goodix_send_mcu_switch_to_fdt_down_no_reply(
          dev, (guint8 *)fdt_switch_state_down_5503,
          sizeof(fdt_switch_state_down_5503), NULL, receive_fdt_down_ack, ssm);
      break;
    case SCAN_STAGE_GET_IMG:
      g_print("SWITCH TO GET IMAGE\n");
      fpi_image_device_report_finger_status(img_dev, TRUE);
      scan_get_img(dev, ssm);
      break;
    case SCAN_STAGE_RESET_SCANNER2:
      g_print("RESET SCANNER\n");
      goodix_send_mcu_switch_to_fdt_mode(
          dev, (guint8 *)fdt_switch_state_mode2_5503,
          sizeof(fdt_switch_state_mode2_5503), NULL, check_none_cmd, ssm);
      break;

    case SCAN_STAGE_SWITCH_TO_FDT_UP_NO_REPLY:
      g_print("SWITCH TO FDT UP NO REPLY\n");
      goodix_send_mcu_switch_to_fdt_up_no_reply(
          dev, (guint8 *)fdt_switch_state_up_5503,
          sizeof(fdt_switch_state_up_5503), NULL, check_none_cmd, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_FDT_UP:
      g_print("SWITCH TO FDT UP\n");
      goodix_send_mcu_switch_to_fdt_up(dev, (guint8 *)fdt_switch_state_up2_5503,
                                       sizeof(fdt_switch_state_up2_5503), NULL,
                                       check_none_cmd, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_FDT_DOWN_NO_REPLY:
      g_print("SWITCH TO FDT DOWN NO REPLY\n");
      goodix_send_mcu_switch_to_fdt_down_no_reply(
          dev, (guint8 *)fdt_switch_state_down2_5503,
          sizeof(fdt_switch_state_down2_5503), NULL, check_none_cmd, ssm);
      break;
    case SCAN_STAGE_QUERY_MCU_TURN_OFF_LIGHT:
      payload.unused_flags = 0x01;
      goodix_send_query_mcu_state(dev, (guint8 *)&payload, sizeof(payload),
                                  check_none_cmd, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_IDLE_MODE:
      g_print("SWITCH TO IDLE MODE\n");
      goodix_send_mcu_switch_to_idle_mode(dev, 20, check_idle, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_SLEEP_MODE:
      g_print("SWITCH TO SLEEP MODE\n");
      goodix_send_mcu_switch_to_sleep_mode(dev, 20, check_idle, ssm);

      break;
    case SCAN_STAGE_SWITCH_TO_FDT_DONE:
      fpi_image_device_report_finger_status(img_dev, FALSE);
      break;
  }
}

static void scan_complete(FpiSsm *ssm, FpDevice *dev, GError *error) {
  if (error) {
    fp_err("failed to scan: %s (code: %d)", error->message, error->code);
    return;
  }
  g_print("finished scan!");
  fp_dbg("finished scan");
}

static void scan_start(FpiDeviceGoodixTls5503 *dev) {
  fpi_ssm_start(fpi_ssm_new(FP_DEVICE(dev), scan_run_state, SCAN_STAGE_NUM),
                scan_complete);
}

// ---- SCAN SECTION END ----

// ---- DEV SECTION START ----

static void dev_init(FpImageDevice *img_dev) {
  FpDevice *dev = FP_DEVICE(img_dev);
  GError *error = NULL;

  if (goodix_dev_init(dev, &error)) {
    fpi_image_device_open_complete(img_dev, error);
    return;
  }

  fpi_image_device_open_complete(img_dev, NULL);
}

static void dev_deinit(FpImageDevice *img_dev) {
  FpDevice *dev = FP_DEVICE(img_dev);
  GError *error = NULL;

  if (goodix_dev_deinit(dev, &error)) {
    fpi_image_device_close_complete(img_dev, error);
    return;
  }

  fpi_image_device_close_complete(img_dev, NULL);
}

static void dev_activate(FpImageDevice *img_dev) {
  FpDevice *dev = FP_DEVICE(img_dev);

  fpi_ssm_start(fpi_ssm_new(dev, activate_run_state, ACTIVATE_NUM_STATES),
                activate_complete);
}

static void dev_change_state(FpImageDevice *img_dev,
                             FpiImageDeviceState state) {
  FpiDeviceGoodixTls5503 *self = FPI_DEVICE_GOODIXTLS5503(img_dev);
  G_DEBUG_HERE();

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON) {
    scan_start(self);
  }
}

static void goodix5503_reset_state(FpiDeviceGoodixTls5503 *self) {}

static void dev_deactivate(FpImageDevice *img_dev) {
  FpDevice *dev = FP_DEVICE(img_dev);
  goodix_reset_state(dev);
  GError *error = NULL;
  goodix_shutdown_tls(dev, &error);
  goodix5503_reset_state(FPI_DEVICE_GOODIXTLS5503(img_dev));
  fpi_image_device_deactivate_complete(img_dev, error);
}

// ---- DEV SECTION END ----

static void fpi_device_goodixtls5503_init(FpiDeviceGoodixTls5503 *self) {
  self->frames = g_slist_alloc();
}

static void fpi_device_goodixtls5503_class_init(
    FpiDeviceGoodixTls5503Class *class) {
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS(class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS(class);
  FpImageDeviceClass *img_dev_class = FP_IMAGE_DEVICE_CLASS(class);

  gx_class->interface = GOODIX_5503_INTERFACE;
  gx_class->ep_in = GOODIX_5503_EP_IN;
  gx_class->ep_out = GOODIX_5503_EP_OUT;

  dev_class->id = "goodixtls5503";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 5503";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages =
      15;  // due to hardware limitations，we set it to 15
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  // TODO
  img_dev_class->bz3_threshold = 10;
  img_dev_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_dev_class->img_width = GOODIX5503_WIDTH;
  img_dev_class->img_height = GOODIX5503_HEIGHT;

  img_dev_class->img_open = dev_init;
  img_dev_class->img_close = dev_deinit;
  img_dev_class->activate = dev_activate;
  img_dev_class->change_state = dev_change_state;
  img_dev_class->deactivate = dev_deactivate;

  fpi_device_class_auto_initialize_features(dev_class);
}
