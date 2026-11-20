// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * MIFARE Classic dictionary attack built on the public poom_nfc API.
 *
 * It walks every sector of the bound card and, for each sector whose key is
 * still unknown, tries the firmware built-in dictionary and then the supplied
 * SD dictionary. Each successful AUTH is cached by the poom_nfc MIFARE layer,
 * so a later read/dump reuses the recovered keys.
 */

#include "poom_nfc_dict.h"

#include <stddef.h>

#include "esp_log.h"
#include "poom_nfc_mifare_classic.h"

static const char* TAG = "poom_nfc_dict_atk";

/* First absolute block of a sector for Mini/1K/4K geometries. */
static uint8_t poom_nfc_dict_first_block_of_sector_(uint8_t sector_count,
                                                    uint8_t sector)
{
    /* 4K: sectors 0..31 are 4 blocks, 32..39 are 16 blocks. */
    if(sector_count > 32U)
    {
        if(sector < 32U)
        {
            return (uint8_t)(sector * 4U);
        }
        return (uint8_t)(128U + ((sector - 32U) * 16U));
    }
    /* Mini (5) and 1K (16): uniform 4-block sectors. */
    return (uint8_t)(sector * 4U);
}

/* Try one key on one sector for one key type; cache happens inside auth. */
static bool poom_nfc_dict_try_key_(uint8_t block,
                                   poom_mifare_key_type_t key_type,
                                   const uint8_t key[POOM_NFC_DICT_KEY_SIZE],
                                   uint32_t* attempts)
{
    if(attempts != NULL)
    {
        (*attempts)++;
    }
    return poom_mifare_classic_auth(block, key_type, key);
}

/*
 * For a single sector + key type, iterate built-ins then the dictionary.
 * Returns true as soon as a working key is found (and thus cached).
 */
static bool poom_nfc_dict_attack_sector_keytype_(
    uint8_t block,
    poom_mifare_key_type_t key_type,
    const poom_nfc_dict_t* dict,
    bool include_builtin,
    poom_nfc_dict_attack_cancel_cb_t cancel_cb,
    void* user_ctx,
    uint32_t* attempts)
{
    if(include_builtin)
    {
        const size_t n = poom_mifare_classic_get_default_key_count();
        for(size_t i = 0U; i < n; i++)
        {
            if((cancel_cb != NULL) && cancel_cb(user_ctx))
            {
                return false;
            }
            const uint8_t* k = poom_mifare_classic_get_default_key(i);
            if(k == NULL)
            {
                continue;
            }
            if(poom_nfc_dict_try_key_(block, key_type, k, attempts))
            {
                return true;
            }
        }
    }

    const size_t dn = poom_nfc_dict_count(dict);
    for(size_t i = 0U; i < dn; i++)
    {
        if((cancel_cb != NULL) && cancel_cb(user_ctx))
        {
            return false;
        }
        const uint8_t* k = poom_nfc_dict_get(dict, i);
        if(k == NULL)
        {
            continue;
        }
        if(poom_nfc_dict_try_key_(block, key_type, k, attempts))
        {
            return true;
        }
    }
    return false;
}

/* Emit a key-found progress event if the sector key is now known. */
static void poom_nfc_dict_emit_found_(
    poom_nfc_dict_attack_progress_cb_t progress_cb,
    void* user_ctx,
    uint8_t sector,
    uint8_t sectors,
    poom_mifare_key_type_t key_type,
    uint32_t attempts)
{
    uint8_t key[POOM_NFC_DICT_KEY_SIZE];
    if(progress_cb == NULL)
    {
        return;
    }
    if(!poom_mifare_classic_get_sector_key(sector, key_type, key))
    {
        return;
    }
    poom_nfc_dict_attack_progress_t ev;
    ev.sector        = sector;
    ev.sectors       = sectors;
    ev.key_type      = (uint8_t)key_type;
    ev.key_found     = true;
    ev.key           = key;
    ev.auth_attempts = attempts;
    progress_cb(&ev, user_ctx);
}

/* Emit a sector-start progress event (no key). */
static void poom_nfc_dict_emit_sector_(
    poom_nfc_dict_attack_progress_cb_t progress_cb,
    void* user_ctx,
    uint8_t sector,
    uint8_t sectors,
    uint32_t attempts)
{
    if(progress_cb == NULL)
    {
        return;
    }
    poom_nfc_dict_attack_progress_t ev;
    ev.sector        = sector;
    ev.sectors       = sectors;
    ev.key_type      = (uint8_t)POOM_MIFARE_KEY_A;
    ev.key_found     = false;
    ev.key           = NULL;
    ev.auth_attempts = attempts;
    progress_cb(&ev, user_ctx);
}

bool poom_nfc_dict_attack_run(const poom_nfc_dict_t* dict,
                              bool try_b,
                              bool include_builtin,
                              poom_nfc_dict_attack_cancel_cb_t cancel_cb,
                              void* user_ctx,
                              poom_nfc_dict_attack_result_t* out)
{
    return poom_nfc_dict_attack_run_ex(dict, try_b, include_builtin, cancel_cb,
                                       NULL, user_ctx, out);
}

bool poom_nfc_dict_attack_run_ex(const poom_nfc_dict_t* dict,
                                 bool try_b,
                                 bool include_builtin,
                                 poom_nfc_dict_attack_cancel_cb_t cancel_cb,
                                 poom_nfc_dict_attack_progress_cb_t progress_cb,
                                 void* user_ctx,
                                 poom_nfc_dict_attack_result_t* out)
{
    poom_nfc_dict_attack_result_t res;
    uint8_t sectors;

    res.sectors          = 0U;
    res.keys_found_a     = 0U;
    res.keys_found_b     = 0U;
    res.sectors_unlocked = 0U;
    res.auth_attempts    = 0U;
    res.canceled         = false;

    /*
     * Force a bind of the active tag by attempting one AUTH. The poom_nfc
     * layer auto-binds the active NFC-A device on the first auth call, so
     * after this get_sector_count() reports the real geometry. The key tried
     * here is just a trigger; a success is a genuine (and cached) hit.
     */
    {
        const uint8_t* seed = NULL;
        if(include_builtin && (poom_mifare_classic_get_default_key_count() > 0U))
        {
            seed = poom_mifare_classic_get_default_key(0);
        }
        else if(poom_nfc_dict_count(dict) > 0U)
        {
            seed = poom_nfc_dict_get(dict, 0);
        }
        if(seed != NULL)
        {
            (void)poom_nfc_dict_try_key_(0U, POOM_MIFARE_KEY_A, seed,
                                         &res.auth_attempts);
        }
    }

    sectors = poom_mifare_classic_get_sector_count();
    if(sectors == 0U)
    {
        ESP_LOGW(TAG, "no MIFARE Classic card bound");
        if(out != NULL)
        {
            *out = res;
        }
        return false;
    }
    res.sectors = sectors;

    for(uint8_t s = 0U; s < sectors; s++)
    {
        if((cancel_cb != NULL) && cancel_cb(user_ctx))
        {
            res.canceled = true;
            break;
        }

        const uint8_t block =
            poom_nfc_dict_first_block_of_sector_(sectors, s);
        uint8_t tmp[POOM_NFC_DICT_KEY_SIZE];

        poom_nfc_dict_emit_sector_(progress_cb, user_ctx, s, sectors,
                                   res.auth_attempts);

        /* Key A */
        if(!poom_mifare_classic_get_sector_key(s, POOM_MIFARE_KEY_A, tmp))
        {
            (void)poom_nfc_dict_attack_sector_keytype_(
                block, POOM_MIFARE_KEY_A, dict, include_builtin, cancel_cb,
                user_ctx, &res.auth_attempts);
        }
        poom_nfc_dict_emit_found_(progress_cb, user_ctx, s, sectors,
                                  POOM_MIFARE_KEY_A, res.auth_attempts);

        /* Key B */
        if(try_b &&
           !poom_mifare_classic_get_sector_key(s, POOM_MIFARE_KEY_B, tmp))
        {
            if((cancel_cb != NULL) && cancel_cb(user_ctx))
            {
                res.canceled = true;
                break;
            }
            (void)poom_nfc_dict_attack_sector_keytype_(
                block, POOM_MIFARE_KEY_B, dict, include_builtin, cancel_cb,
                user_ctx, &res.auth_attempts);
        }
        if(try_b)
        {
            poom_nfc_dict_emit_found_(progress_cb, user_ctx, s, sectors,
                                      POOM_MIFARE_KEY_B, res.auth_attempts);
        }
    }

    /* Tally final state. */
    for(uint8_t s = 0U; s < sectors; s++)
    {
        uint8_t tmp[POOM_NFC_DICT_KEY_SIZE];
        bool any = false;
        if(poom_mifare_classic_get_sector_key(s, POOM_MIFARE_KEY_A, tmp))
        {
            res.keys_found_a++;
            any = true;
        }
        if(poom_mifare_classic_get_sector_key(s, POOM_MIFARE_KEY_B, tmp))
        {
            res.keys_found_b++;
            any = true;
        }
        if(any)
        {
            res.sectors_unlocked++;
        }
    }

    ESP_LOGI(TAG,
             "dict attack: %u/%u sectors unlocked (A=%u B=%u) in %u auths%s",
             res.sectors_unlocked, res.sectors, res.keys_found_a,
             res.keys_found_b, (unsigned)res.auth_attempts,
             res.canceled ? " [canceled]" : "");

    if(out != NULL)
    {
        *out = res;
    }
    return res.sectors_unlocked > 0U;
}
