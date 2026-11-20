// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_dict.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "poom_nfc_mifare_classic.h"
#include "sd_card.h"

static const char* TAG = "poom_nfc_dict";

static poom_nfc_dict_t s_active_dict;

poom_nfc_dict_t* poom_nfc_dict_active(void)
{
    return &s_active_dict;
}

void poom_nfc_dict_clear(poom_nfc_dict_t* dict)
{
    if(dict == NULL)
    {
        return;
    }
    dict->count     = 0U;
    dict->truncated = false;
    dict->name[0]   = '\0';
    /* Key bytes are left as-is; count gates all reads. */
}

size_t poom_nfc_dict_count(const poom_nfc_dict_t* dict)
{
    return (dict != NULL) ? dict->count : 0U;
}

const uint8_t* poom_nfc_dict_get(const poom_nfc_dict_t* dict, size_t idx)
{
    if((dict == NULL) || (idx >= dict->count))
    {
        return NULL;
    }
    return dict->keys[idx];
}

static bool poom_nfc_dict_contains_(const poom_nfc_dict_t* dict,
                                    const uint8_t key[POOM_NFC_DICT_KEY_SIZE])
{
    for(size_t i = 0U; i < dict->count; i++)
    {
        if(memcmp(dict->keys[i], key, POOM_NFC_DICT_KEY_SIZE) == 0)
        {
            return true;
        }
    }
    return false;
}

bool poom_nfc_dict_add_key(poom_nfc_dict_t* dict,
                           const uint8_t key[POOM_NFC_DICT_KEY_SIZE])
{
    if((dict == NULL) || (key == NULL))
    {
        return false;
    }
    if(dict->count >= POOM_NFC_DICT_MAX_KEYS)
    {
        dict->truncated = true;
        return false;
    }
    if(poom_nfc_dict_contains_(dict, key))
    {
        return false;
    }
    memcpy(dict->keys[dict->count], key, POOM_NFC_DICT_KEY_SIZE);
    dict->count++;
    return true;
}

/* Parse exactly 12 hex nibbles from @p line into @p out[6]. */
static bool poom_nfc_dict_parse_key_line_(const char* line,
                                          uint8_t out[POOM_NFC_DICT_KEY_SIZE])
{
    uint8_t nibbles[2U * POOM_NFC_DICT_KEY_SIZE];
    size_t n = 0U;

    for(const char* p = line; *p != '\0'; p++)
    {
        const unsigned char c = (unsigned char)*p;

        if(isspace(c))
        {
            continue;
        }
        /* Comment markers end the usable portion of the line. */
        if((c == '#') || (c == ';'))
        {
            break;
        }
        if((c == '/') && (p[1] == '/'))
        {
            break;
        }
        if(!isxdigit(c))
        {
            return false; /* unexpected character -> reject line */
        }
        if(n >= sizeof(nibbles))
        {
            return false; /* too long */
        }

        uint8_t v;
        if((c >= '0') && (c <= '9'))
        {
            v = (uint8_t)(c - '0');
        }
        else
        {
            v = (uint8_t)((tolower(c) - 'a') + 10);
        }
        nibbles[n++] = v;
    }

    if(n != sizeof(nibbles))
    {
        return false; /* must be exactly 12 hex digits */
    }

    for(size_t i = 0U; i < POOM_NFC_DICT_KEY_SIZE; i++)
    {
        out[i] = (uint8_t)((nibbles[2U * i] << 4) | nibbles[(2U * i) + 1U]);
    }
    return true;
}

static void poom_nfc_dict_build_abs_(const char* filename, char* out, size_t out_len)
{
    if((filename != NULL) && (filename[0] == '/'))
    {
        (void)snprintf(out, out_len, "%s%s", SD_CARD_PATH, filename);
    }
    else
    {
        (void)snprintf(out, out_len, "%s%s/%s", SD_CARD_PATH,
                       POOM_NFC_DICT_DIR_REL,
                       (filename != NULL) ? filename : POOM_NFC_DICT_DEFAULT_FILE);
    }
}

static void poom_nfc_dict_set_name_(poom_nfc_dict_t* dict, const char* filename)
{
    const char* base = filename;
    if(base == NULL)
    {
        base = POOM_NFC_DICT_DEFAULT_FILE;
    }
    const char* slash = strrchr(base, '/');
    if(slash != NULL)
    {
        base = slash + 1;
    }
    (void)snprintf(dict->name, sizeof(dict->name), "%s", base);
}

esp_err_t poom_nfc_dict_load_file(const char* filename, poom_nfc_dict_t* dict)
{
    char abs_path[160];
    char line[64];
    FILE* f;
    size_t parsed = 0U;
    size_t rejected = 0U;

    if(dict == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }
    if(sd_card_is_not_mounted())
    {
        ESP_LOGE(TAG, "SD card not mounted");
        return ESP_FAIL;
    }

    poom_nfc_dict_clear(dict);
    poom_nfc_dict_build_abs_(filename, abs_path, sizeof(abs_path));

    f = fopen(abs_path, "r");
    if(f == NULL)
    {
        ESP_LOGE(TAG, "open failed: %s", abs_path);
        return ESP_ERR_NOT_FOUND;
    }

    while(fgets(line, sizeof(line), f) != NULL)
    {
        uint8_t key[POOM_NFC_DICT_KEY_SIZE];

        /* Skip empty / comment-only lines silently. */
        const char* p = line;
        while((*p != '\0') && isspace((unsigned char)*p))
        {
            p++;
        }
        if((*p == '\0') || (*p == '#') || (*p == ';') ||
           ((*p == '/') && (p[1] == '/')))
        {
            continue;
        }

        if(poom_nfc_dict_parse_key_line_(line, key))
        {
            if(poom_nfc_dict_add_key(dict, key))
            {
                parsed++;
            }
            if(dict->truncated)
            {
                ESP_LOGW(TAG, "dictionary capped at %u keys",
                         (unsigned)POOM_NFC_DICT_MAX_KEYS);
                break;
            }
        }
        else
        {
            rejected++;
        }
    }

    (void)fclose(f);
    poom_nfc_dict_set_name_(dict, filename);

    ESP_LOGI(TAG, "loaded %u keys from %s (%u rejected)", (unsigned)parsed,
             dict->name, (unsigned)rejected);
    return ESP_OK;
}

esp_err_t poom_nfc_dict_write_builtin(const char* filename, size_t* out_written)
{
    char abs_path[160];
    FILE* f;
    const size_t n = poom_mifare_classic_get_default_key_count();
    size_t written = 0U;

    if(out_written != NULL)
    {
        *out_written = 0U;
    }
    if(sd_card_is_not_mounted())
    {
        ESP_LOGE(TAG, "SD card not mounted");
        return ESP_FAIL;
    }

    /* Ensure /nfc and /nfc/dict exist (FatFs drive-relative paths). */
    (void)sd_card_create_dir("/nfc");
    (void)sd_card_create_dir(POOM_NFC_DICT_DIR_REL);

    poom_nfc_dict_build_abs_((filename != NULL) ? filename
                                                : POOM_NFC_DICT_DEFAULT_FILE,
                             abs_path, sizeof(abs_path));

    f = fopen(abs_path, "w");
    if(f == NULL)
    {
        ESP_LOGE(TAG, "create failed: %s", abs_path);
        return ESP_FAIL;
    }

    (void)fprintf(f, "# POOM built-in MIFARE Classic key dictionary\r\n");
    (void)fprintf(f, "# One 6-byte key per line (12 hex chars). Edit freely.\r\n");

    for(size_t i = 0U; i < n; i++)
    {
        const uint8_t* k = poom_mifare_classic_get_default_key(i);
        if(k == NULL)
        {
            continue;
        }
        if(fprintf(f, "%02X%02X%02X%02X%02X%02X\r\n", k[0], k[1], k[2], k[3],
                   k[4], k[5]) < 0)
        {
            (void)fclose(f);
            ESP_LOGE(TAG, "write error at key %u", (unsigned)i);
            return ESP_FAIL;
        }
        written++;
    }

    (void)fclose(f);
    if(out_written != NULL)
    {
        *out_written = written;
    }
    ESP_LOGI(TAG, "wrote %u keys to %s", (unsigned)written, abs_path);
    return ESP_OK;
}

static bool poom_nfc_dict_has_dic_ext_(const char* name)
{
    const size_t len = strlen(name);
    const size_t ext = strlen(POOM_NFC_DICT_EXT);
    if(len <= ext)
    {
        return false;
    }
    return strcasecmp(name + (len - ext), POOM_NFC_DICT_EXT) == 0;
}

esp_err_t poom_nfc_dict_list_files(poom_nfc_dict_list_cb_t cb, void* user_ctx)
{
    char dir_abs[96];
    DIR* dir;
    struct dirent* ent;

    if(sd_card_is_not_mounted())
    {
        return ESP_FAIL;
    }

    (void)snprintf(dir_abs, sizeof(dir_abs), "%s%s", SD_CARD_PATH,
                   POOM_NFC_DICT_DIR_REL);

    dir = opendir(dir_abs);
    if(dir == NULL)
    {
        return ESP_ERR_NOT_FOUND;
    }

    while((ent = readdir(dir)) != NULL)
    {
        if(ent->d_name[0] == '.')
        {
            continue;
        }
        if(!poom_nfc_dict_has_dic_ext_(ent->d_name))
        {
            continue;
        }

        size_t size_bytes = 0U;
        char file_abs[384];
        struct stat st;
        (void)snprintf(file_abs, sizeof(file_abs), "%s/%s", dir_abs,
                       ent->d_name);
        if(stat(file_abs, &st) == 0)
        {
            size_bytes = (size_t)st.st_size;
        }

        if((cb != NULL) && !cb(ent->d_name, size_bytes, user_ctx))
        {
            break;
        }
    }

    (void)closedir(dir);
    return ESP_OK;
}
