// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * SD-card MIFARE key dictionaries + dictionary attack.
 *
 * Mirrors the Chameleon Ultra / Proxmark / Flipper workflow: keys live in
 * editable ".dic" text files on the SD card (one 12-hex-character key per
 * line; "#", ";" or "//" comments and blank lines ignored). A loaded
 * dictionary is fed to a MIFARE Classic key-discovery (dictionary attack)
 * built on top of the public poom_nfc MIFARE API, in addition to the
 * firmware's built-in default keys.
 *
 * This component lives in the POOM application repository (not the poom_nfc
 * submodule) and depends only on poom_nfc's public interface.
 *
 * Intended for authorized testing and development only.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_DICT_KEY_SIZE (6U)

/* Max keys held in a single in-RAM dictionary (2048 * 6 = 12 KiB). */
#define POOM_NFC_DICT_MAX_KEYS (2048U)

/* SD layout (FatFs drive-relative paths; file I/O uses SD_CARD_PATH prefix). */
#define POOM_NFC_DICT_DIR_REL      "/nfc/dict"
#define POOM_NFC_DICT_DEFAULT_FILE "mf_default_keys.dic"
#define POOM_NFC_DICT_NAME_MAX     (64U)
#define POOM_NFC_DICT_EXT          ".dic"

typedef struct
{
    uint8_t keys[POOM_NFC_DICT_MAX_KEYS][POOM_NFC_DICT_KEY_SIZE];
    size_t count;
    char name[POOM_NFC_DICT_NAME_MAX];
    bool truncated; /* true if the source held more keys than MAX_KEYS */
} poom_nfc_dict_t;

/* ---- dictionary container ------------------------------------------------ */

/**
 * @brief Access the single process-wide "active" dictionary instance.
 *
 * Loading a file populates this instance; the MIFARE menu read and the
 * dictionary-attack command consult it.
 */
poom_nfc_dict_t* poom_nfc_dict_active(void);

/** Reset a dictionary to empty. */
void poom_nfc_dict_clear(poom_nfc_dict_t* dict);

/**
 * @brief Append a key, ignoring exact duplicates already present.
 * @return true if stored, false if full or duplicate.
 */
bool poom_nfc_dict_add_key(poom_nfc_dict_t* dict,
                           const uint8_t key[POOM_NFC_DICT_KEY_SIZE]);

size_t poom_nfc_dict_count(const poom_nfc_dict_t* dict);

const uint8_t* poom_nfc_dict_get(const poom_nfc_dict_t* dict, size_t idx);

/* ---- SD-card persistence ------------------------------------------------- */

/**
 * @brief Load a ".dic" file from the SD card into @p dict (replaces contents).
 *
 * @param[in] filename Name under POOM_NFC_DICT_DIR_REL (e.g. "mykeys.dic"),
 *            or an absolute SD path beginning with '/'.
 * @param[out] dict Destination (cleared first).
 * @return ESP_OK on success (0 keys is still OK), ESP_ERR_* otherwise.
 */
esp_err_t poom_nfc_dict_load_file(const char* filename, poom_nfc_dict_t* dict);

/**
 * @brief Write the firmware's built-in default MIFARE key dictionary to SD.
 *
 * Produces an editable ".dic" (same format Chameleon Ultra / Proxmark use) so
 * the on-device defaults are available on the card and can be customized.
 *
 * @param[in] filename Target name under POOM_NFC_DICT_DIR_REL, or NULL for the
 *            default (POOM_NFC_DICT_DEFAULT_FILE).
 * @param[out] out_written Optional count of keys written.
 * @return ESP_OK on success.
 */
esp_err_t poom_nfc_dict_write_builtin(const char* filename, size_t* out_written);

/** Callback for poom_nfc_dict_list_files(); return false to stop early. */
typedef bool (*poom_nfc_dict_list_cb_t)(const char* filename,
                                        size_t size_bytes,
                                        void* user_ctx);

/**
 * @brief Enumerate ".dic" files in POOM_NFC_DICT_DIR_REL.
 * @return ESP_OK (even when empty), ESP_ERR_* if the directory can't be opened.
 */
esp_err_t poom_nfc_dict_list_files(poom_nfc_dict_list_cb_t cb, void* user_ctx);

/* ---- dictionary attack --------------------------------------------------- */

typedef struct
{
    uint8_t sectors;       /* sector count of the bound card                 */
    uint8_t keys_found_a;  /* sectors with a known Key A after the run       */
    uint8_t keys_found_b;  /* sectors with a known Key B after the run       */
    uint8_t sectors_unlocked; /* sectors with at least one known key         */
    uint32_t auth_attempts;   /* number of AUTH attempts performed           */
    bool canceled;
} poom_nfc_dict_attack_result_t;

/** Cooperative cancellation predicate; return true to stop the attack. */
typedef bool (*poom_nfc_dict_attack_cancel_cb_t)(void* user_ctx);

/**
 * @brief Live progress event emitted during a dictionary attack.
 *
 * Lets an on-device UI render keys as they are recovered, matching the
 * Chameleon Ultra / Flipper "keys appear live on screen" experience.
 * Two kinds of event are emitted:
 *   - sector start: @ref key_found is false, @ref sector / @ref sectors set;
 *   - key found: @ref key_found is true and @ref key points at the 6 recovered
 *     key bytes for (@ref sector, @ref key_type). @ref key is valid only for
 *     the duration of the callback.
 */
typedef struct
{
    uint8_t  sector;        /* sector this event concerns                     */
    uint8_t  sectors;       /* total sectors on the bound card                */
    uint8_t  key_type;      /* poom_mifare_key_type_t of this event           */
    bool     key_found;     /* true for a key-found event, false for progress */
    const uint8_t* key;     /* 6 key bytes when key_found, else NULL          */
    uint32_t auth_attempts; /* running AUTH attempt count                     */
} poom_nfc_dict_attack_progress_t;

/** Progress sink; invoked on the calling task. Keep it short (UI redraw). */
typedef void (*poom_nfc_dict_attack_progress_cb_t)(
    const poom_nfc_dict_attack_progress_t* ev, void* user_ctx);

/**
 * @brief Dictionary attack with live per-sector/per-key progress reporting.
 *
 * Identical to poom_nfc_dict_attack_run() but also invokes @p progress_cb as
 * each sector is started and each key recovered, so callers can draw a live
 * key table. @p progress_cb and @p cancel_cb share @p user_ctx.
 */
bool poom_nfc_dict_attack_run_ex(const poom_nfc_dict_t* dict,
                                 bool try_b,
                                 bool include_builtin,
                                 poom_nfc_dict_attack_cancel_cb_t cancel_cb,
                                 poom_nfc_dict_attack_progress_cb_t progress_cb,
                                 void* user_ctx,
                                 poom_nfc_dict_attack_result_t* out);

/**
 * @brief Run a MIFARE Classic dictionary attack across every sector.
 *
 * Requires a card to be present (the RF field active and a MIFARE Classic
 * tag in range); the attack auto-binds the active tag on its first AUTH.
 * Successful keys are cached by the poom_nfc MIFARE layer, so a subsequent
 * read/dump uses them automatically.
 *
 * Order of keys tried per unknown sector: the firmware built-in dictionary
 * (when @p include_builtin) followed by @p dict's keys.
 *
 * @param[in] dict Key dictionary to try (may be NULL to use built-ins only).
 * @param[in] try_b Also attempt Key B per sector.
 * @param[in] include_builtin Also try the firmware's built-in default keys.
 * @param[in] cancel_cb Optional cancellation predicate.
 * @param[in] user_ctx Passed to @p cancel_cb.
 * @param[out] out Optional result counters.
 * @return true if at least one key is known for the card after the run.
 */
bool poom_nfc_dict_attack_run(const poom_nfc_dict_t* dict,
                              bool try_b,
                              bool include_builtin,
                              poom_nfc_dict_attack_cancel_cb_t cancel_cb,
                              void* user_ctx,
                              poom_nfc_dict_attack_result_t* out);

#ifdef __cplusplus
}
#endif
