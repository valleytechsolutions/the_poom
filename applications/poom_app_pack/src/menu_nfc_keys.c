// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * ZEN > NFC > KEYS: on-device MIFARE Classic key-recovery scene.
 *
 * Present a card, watch sector keys appear live as the dictionary attack
 * recovers them (Chameleon Ultra / Flipper style), then dump the card to an
 * SD .nfc file with the recovered keys. Built on the POOM's existing poom_nfc
 * RF stack + poom_nfc_dict, no CLI required.
 */

#include "menu_nfc_keys.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Arduboy2.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "input_events.h"
#include "poom_sbus.h"

#include "poom_nfc_card_ident.h"
#include "poom_nfc_cards.h"
#include "poom_nfc_controller.h"
#include "poom_nfc_dict.h"
#include "poom_nfc_dump.h"
#include "poom_nfc_mifare_classic.h"

#define POOM_MENU_RESUME_TOPIC "poom/menu/resume"

#define MENU_NFC_KEYS_REFRESH_MS (150U)
#define MENU_NFC_KEYS_STACK (4608U)
#define MENU_NFC_KEYS_PRIO (4U)

#define MENU_NFC_KEYS_MAX_SECTORS (40U)
#define MENU_NFC_KEYS_SCAN_MS (1500U)
#define MENU_NFC_KEYS_DUMP_DIR "/nfc"

#define HEADER_H (11)

#ifndef BTN_A
#define BTN_A (0U)
#endif
#ifndef BTN_B
#define BTN_B (1U)
#endif
#ifndef BTN_LEFT
#define BTN_LEFT (2U)
#endif
#ifndef BTN_RIGHT
#define BTN_RIGHT (3U)
#endif
#ifndef BTN_UP
#define BTN_UP (4U)
#endif
#ifndef BTN_DOWN
#define BTN_DOWN (5U)
#endif
#ifndef BUTTON_SINGLE_CLICK
#define BUTTON_SINGLE_CLICK (4U)
#endif

typedef enum
{
    KEYS_STATE_IDLE = 0,
    KEYS_STATE_RECOVER,
    KEYS_STATE_DONE,
    KEYS_STATE_VIEW,
} menu_nfc_keys_state_t;

typedef struct
{
    uint8_t button;
    uint8_t event;
} menu_nfc_keys_button_msg_t;

/* ---- scene lifetime ------------------------------------------------------ */
static bool s_active = false;
static bool s_buttons_subscribed = false;
static bool s_exit_requested = false;
static bool s_cancel_requested = false;
static bool s_rf_live = false;
static TaskHandle_t s_ui_task = NULL;
static QueueHandle_t s_btn_q = NULL;
static char s_sbus_user[] = "menu_nfc_keys";

/* ---- recovery model ------------------------------------------------------ */
static menu_nfc_keys_state_t s_state = KEYS_STATE_IDLE;
static uint8_t s_sec_cnt = 0U;
static uint8_t s_cur = 0U;
static bool s_a_known[MENU_NFC_KEYS_MAX_SECTORS];
static bool s_b_known[MENU_NFC_KEYS_MAX_SECTORS];
static uint8_t s_a_key[MENU_NFC_KEYS_MAX_SECTORS][6];
static uint8_t s_b_key[MENU_NFC_KEYS_MAX_SECTORS][6];
static uint8_t s_found_a = 0U;
static uint8_t s_found_b = 0U;
static uint8_t s_unlocked = 0U;
static char s_card_name[12] = "";
static char s_status[22] = "READY";
static uint16_t s_view_block = 0U;  /* block browsed in KEYS_STATE_VIEW       */

static void menu_nfc_keys_button_cb_(const poom_sbus_msg_t* msg, void* user_ctx);
static void menu_nfc_keys_ui_task_(void* arg);

/* ---- drawing ------------------------------------------------------------- */

static void menu_nfc_keys_header_(const char* title)
{
    poom_arduboy_set_text_size(1);
    poom_arduboy_set_cursor(2, 2);
    (void)poom_arduboy_print(title);
    poom_arduboy_fill_rect(0, 0, ARDUBOY_WIDTH, HEADER_H, INVERT);
}

static void menu_nfc_keys_draw_idle_(void)
{
    poom_arduboy_clear();
    menu_nfc_keys_header_("MIFARE KEYS");

    poom_arduboy_set_cursor(6, 20);
    (void)poom_arduboy_print(F("Present a MIFARE"));
    poom_arduboy_set_cursor(6, 30);
    (void)poom_arduboy_print(F("Classic card."));

    poom_arduboy_set_cursor(0, 56);
    (void)poom_arduboy_print(F("A:START"));
    poom_arduboy_set_cursor(85, 56);
    (void)poom_arduboy_print(F("B:BACK"));
    poom_arduboy_display();
}

static void menu_nfc_keys_draw_busy_(const char* line)
{
    poom_arduboy_clear();
    menu_nfc_keys_header_("MIFARE KEYS");
    poom_arduboy_set_cursor(6, 26);
    (void)poom_arduboy_print(line ? line : "Working...");
    poom_arduboy_set_cursor(72, 56);
    (void)poom_arduboy_print(F("B:STOP"));
    poom_arduboy_display();
}

/* 12-hex of a 6-byte key into dst[13]. */
static void menu_nfc_keys_fmt_key_(const uint8_t key[6], char* dst)
{
    (void)snprintf(dst, 13, "%02X%02X%02X%02X%02X%02X",
                   key[0], key[1], key[2], key[3], key[4], key[5]);
}

/* Live view: progress line + a scrolling window of sector keys around s_cur. */
static void menu_nfc_keys_draw_live_(void)
{
    char line[40];

    poom_arduboy_clear();
    menu_nfc_keys_header_("MIFARE KEYS");

    (void)snprintf(line, sizeof(line), "S%02u/%02u A:%u B:%u",
                   (unsigned)(s_cur + 1U), (unsigned)s_sec_cnt,
                   (unsigned)s_found_a, (unsigned)s_found_b);
    poom_arduboy_set_cursor(2, 13);
    (void)poom_arduboy_print(line);

    /* Window of 4 sectors, anchored so the current one stays visible. */
    uint8_t first = 0U;
    if(s_sec_cnt > 4U)
    {
        if(s_cur >= 2U)
        {
            first = (uint8_t)(s_cur - 2U);
        }
        if(first > (uint8_t)(s_sec_cnt - 4U))
        {
            first = (uint8_t)(s_sec_cnt - 4U);
        }
    }

    for(uint8_t row = 0U; row < 4U; row++)
    {
        const uint8_t s = (uint8_t)(first + row);
        const int16_t y = (int16_t)(23 + row * 9);
        if(s >= s_sec_cnt)
        {
            break;
        }
        char keyhex[13];
        char tag;
        if(s_a_known[s])
        {
            menu_nfc_keys_fmt_key_(s_a_key[s], keyhex);
            tag = 'A';
        }
        else if(s_b_known[s])
        {
            menu_nfc_keys_fmt_key_(s_b_key[s], keyhex);
            tag = 'B';
        }
        else
        {
            (void)snprintf(keyhex, sizeof(keyhex), "------------");
            tag = (s == s_cur) ? '>' : ' ';
        }
        (void)snprintf(line, sizeof(line), "%c%02u %s",
                       tag, (unsigned)s, keyhex);
        poom_arduboy_set_cursor(2, y);
        (void)poom_arduboy_print(line);
    }

    poom_arduboy_set_cursor(72, 56);
    (void)poom_arduboy_print(F("B:STOP"));
    poom_arduboy_display();
}

static void menu_nfc_keys_draw_done_(void)
{
    char line[40];

    poom_arduboy_clear();
    menu_nfc_keys_header_("MIFARE KEYS");

    (void)snprintf(line, sizeof(line), "%s", s_card_name[0] ? s_card_name : "CARD");
    poom_arduboy_set_cursor(2, 14);
    (void)poom_arduboy_print(line);

    (void)snprintf(line, sizeof(line), "Unlock %u/%u sec",
                   (unsigned)s_unlocked, (unsigned)s_sec_cnt);
    poom_arduboy_set_cursor(2, 24);
    (void)poom_arduboy_print(line);

    (void)snprintf(line, sizeof(line), "Keys A:%u B:%u",
                   (unsigned)s_found_a, (unsigned)s_found_b);
    poom_arduboy_set_cursor(2, 34);
    (void)poom_arduboy_print(line);

    poom_arduboy_set_cursor(2, 44);
    (void)poom_arduboy_print(s_status);

    poom_arduboy_set_cursor(0, 56);
    (void)poom_arduboy_print(F("A:DMP >:DAT v:KEYS"));
    poom_arduboy_set_cursor(110, 56);
    (void)poom_arduboy_print(F("B"));
    poom_arduboy_display();
}

/* On-screen block/data viewer: read the selected block with the recovered
 * keys and show its 16 bytes. Requires RF still live (left up after recover). */
static void menu_nfc_keys_draw_view_(void)
{
    char line[40];
    uint8_t data[16];
    const int sec = poom_mifare_classic_sector_for_block((uint8_t)s_view_block);

    poom_arduboy_clear();
    menu_nfc_keys_header_("MIFARE DATA");

    if(sec >= 0)
    {
        (void)snprintf(line, sizeof(line), "Blk %u  Sec %d",
                       (unsigned)s_view_block, sec);
    }
    else
    {
        (void)snprintf(line, sizeof(line), "Blk %u", (unsigned)s_view_block);
    }
    poom_arduboy_set_cursor(2, 13);
    (void)poom_arduboy_print(line);

    if(poom_mifare_classic_read_block((uint8_t)s_view_block, data))
    {
        (void)snprintf(line, sizeof(line), "%02X%02X%02X%02X %02X%02X%02X%02X",
                       data[0], data[1], data[2], data[3],
                       data[4], data[5], data[6], data[7]);
        poom_arduboy_set_cursor(2, 26);
        (void)poom_arduboy_print(line);
        (void)snprintf(line, sizeof(line), "%02X%02X%02X%02X %02X%02X%02X%02X",
                       data[8], data[9], data[10], data[11],
                       data[12], data[13], data[14], data[15]);
        poom_arduboy_set_cursor(2, 36);
        (void)poom_arduboy_print(line);
    }
    else
    {
        poom_arduboy_set_cursor(2, 30);
        (void)poom_arduboy_print(F("<no key / locked>"));
    }

    poom_arduboy_set_cursor(0, 56);
    (void)poom_arduboy_print(F("UP/DN:BLK"));
    poom_arduboy_set_cursor(97, 56);
    (void)poom_arduboy_print(F("B:BK"));
    poom_arduboy_display();
}

/* ---- attack progress sink (runs on the UI task) -------------------------- */

static bool menu_nfc_keys_cancel_cb_(void* user_ctx)
{
    (void)user_ctx;
    return s_cancel_requested || s_exit_requested || !s_active;
}

static void menu_nfc_keys_recount_(void)
{
    s_found_a = 0U;
    s_found_b = 0U;
    s_unlocked = 0U;
    for(uint8_t s = 0U; s < s_sec_cnt; s++)
    {
        bool any = false;
        if(s_a_known[s])
        {
            s_found_a++;
            any = true;
        }
        if(s_b_known[s])
        {
            s_found_b++;
            any = true;
        }
        if(any)
        {
            s_unlocked++;
        }
    }
}

static void menu_nfc_keys_progress_cb_(
    const poom_nfc_dict_attack_progress_t* ev, void* user_ctx)
{
    (void)user_ctx;
    if(ev == NULL)
    {
        return;
    }
    if(ev->sectors > 0U && ev->sectors <= MENU_NFC_KEYS_MAX_SECTORS)
    {
        s_sec_cnt = ev->sectors;
    }
    if(ev->sector < MENU_NFC_KEYS_MAX_SECTORS)
    {
        s_cur = ev->sector;
    }

    if(ev->key_found && ev->key != NULL && ev->sector < MENU_NFC_KEYS_MAX_SECTORS)
    {
        if((poom_mifare_key_type_t)ev->key_type == POOM_MIFARE_KEY_B)
        {
            memcpy(s_b_key[ev->sector], ev->key, 6);
            s_b_known[ev->sector] = true;
        }
        else
        {
            memcpy(s_a_key[ev->sector], ev->key, 6);
            s_a_known[ev->sector] = true;
        }
        menu_nfc_keys_recount_();
    }

    menu_nfc_keys_draw_live_();
}

/* ---- card bring-up + recovery -------------------------------------------- */

static nfc_card_type_t menu_nfc_keys_detect_(const poom_nfc_dump_t* dump)
{
    if(dump == NULL || !poom_nfc_card_id_is_valid(&dump->id))
    {
        return NFC_CARD_UNKNOWN;
    }
    if(((dump->id.flags & POOM_NFC_CARD_FLAG_ATQA_SET) == 0U) ||
       ((dump->id.flags & POOM_NFC_CARD_FLAG_SAK_SET) == 0U))
    {
        return NFC_CARD_UNKNOWN;
    }
    const uint16_t atqa =
        (uint16_t)((uint16_t)dump->id.atqa[1] << 8) | (uint16_t)dump->id.atqa[0];
    return nfc_ident_detect_nfca(atqa, dump->id.sak);
}

static void menu_nfc_keys_reset_model_(void)
{
    s_sec_cnt = 0U;
    s_cur = 0U;
    s_found_a = 0U;
    s_found_b = 0U;
    s_unlocked = 0U;
    (void)memset(s_a_known, 0, sizeof(s_a_known));
    (void)memset(s_b_known, 0, sizeof(s_b_known));
    s_card_name[0] = '\0';
}

static void menu_nfc_keys_stop_rf_(void)
{
    if(s_rf_live)
    {
        poom_nfc_controller_stop();
        s_rf_live = false;
    }
}

/* Scan + bind + run the dictionary attack with live progress. Leaves RF up
 * and the card bound on success so a following DUMP reuses the session. */
static void menu_nfc_keys_recover_(void)
{
    poom_nfc_dump_t dump;

    s_cancel_requested = false;
    menu_nfc_keys_reset_model_();
    menu_nfc_keys_draw_busy_("Scanning...");

    if(!poom_nfc_controller_start())
    {
        (void)snprintf(s_status, sizeof(s_status), "RF START FAIL");
        s_state = KEYS_STATE_DONE;
        return;
    }
    s_rf_live = true;

    if(!poom_nfc_controller_capture_probe(MENU_NFC_KEYS_SCAN_MS, &dump) ||
       !poom_nfc_card_id_is_valid(&dump.id))
    {
        (void)snprintf(s_status, sizeof(s_status), "NO CARD");
        menu_nfc_keys_stop_rf_();
        s_state = KEYS_STATE_DONE;
        return;
    }

    const nfc_card_type_t type = menu_nfc_keys_detect_(&dump);
    if(!poom_mifare_classic_is_supported_card(type))
    {
        (void)snprintf(s_status, sizeof(s_status), "NOT MFC");
        menu_nfc_keys_stop_rf_();
        s_state = KEYS_STATE_DONE;
        return;
    }
    (void)snprintf(s_card_name, sizeof(s_card_name), "%s",
                   nfc_ident_card_type_to_str(type));

    if(!poom_nfc_controller_connect() ||
       !poom_mifare_classic_bind_card(dump.id.uid, dump.id.uid_len, type))
    {
        (void)snprintf(s_status, sizeof(s_status), "BIND FAIL");
        menu_nfc_keys_stop_rf_();
        s_state = KEYS_STATE_DONE;
        return;
    }

    menu_nfc_keys_draw_busy_("Recovering keys...");

    poom_nfc_dict_attack_result_t res;
    (void)poom_nfc_dict_attack_run_ex(poom_nfc_dict_active(),
                                      true /* try Key B */,
                                      true /* built-in dict */,
                                      menu_nfc_keys_cancel_cb_,
                                      menu_nfc_keys_progress_cb_,
                                      NULL, &res);

    menu_nfc_keys_recount_();
    if(res.canceled)
    {
        (void)snprintf(s_status, sizeof(s_status), "STOPPED");
    }
    else if(s_unlocked == s_sec_cnt && s_sec_cnt > 0U)
    {
        (void)snprintf(s_status, sizeof(s_status), "ALL KEYS FOUND");
    }
    else
    {
        (void)snprintf(s_status, sizeof(s_status), "PARTIAL");
    }
    s_state = KEYS_STATE_DONE;
    /* RF left live so DUMP can reuse the bound card/keys. */
}

/* Fold every recovered sector key into the active dictionary and persist it
 * to SD, so the keys are reused by later attacks and survive a power cycle. */
static void menu_nfc_keys_save_keys_(void)
{
    size_t added = 0U;
    size_t written = 0U;

    for(uint8_t s = 0U; s < s_sec_cnt; s++)
    {
        if(s_a_known[s] && poom_nfc_dict_add_key(poom_nfc_dict_active(),
                                                 s_a_key[s]))
        {
            added++;
        }
        if(s_b_known[s] && poom_nfc_dict_add_key(poom_nfc_dict_active(),
                                                 s_b_key[s]))
        {
            added++;
        }
    }
    (void)added;

    const esp_err_t err = poom_nfc_dict_save_file(
        "recovered.dic", poom_nfc_dict_active(), &written);
    if(err == ESP_OK)
    {
        (void)snprintf(s_status, sizeof(s_status), "SAVED %u KEYS",
                       (unsigned)written);
    }
    else
    {
        (void)snprintf(s_status, sizeof(s_status), "SAVE FAIL");
    }
}

static void menu_nfc_keys_dump_(void)
{
    char path[96];
    char rel[80];

    if(!s_rf_live)
    {
        if(!poom_nfc_controller_start())
        {
            (void)snprintf(s_status, sizeof(s_status), "RF START FAIL");
            return;
        }
        s_rf_live = true;
    }

    menu_nfc_keys_draw_busy_("Dumping to SD...");
    rel[0] = '\0';
    const bool ok = poom_mifare_classic_dump_to_flipper_file(
        MENU_NFC_KEYS_DUMP_DIR, true, rel, sizeof(rel));
    if(ok)
    {
        /* Show just the file name to fit the screen. */
        const char* base = strrchr(rel, '/');
        (void)snprintf(path, sizeof(path), "%s", base ? (base + 1) : rel);
        (void)snprintf(s_status, sizeof(s_status), "SAVED %.15s", path);
    }
    else
    {
        (void)snprintf(s_status, sizeof(s_status), "DUMP FAIL");
    }
}

/* ---- buttons + task ------------------------------------------------------ */

static void menu_nfc_keys_button_cb_(const poom_sbus_msg_t* msg, void* user_ctx)
{
    (void)user_ctx;
    if(!s_active || msg == NULL || msg->len < sizeof(button_event_msg_t) ||
       s_btn_q == NULL)
    {
        return;
    }
    button_event_msg_t ev;
    memcpy(&ev, msg->data, sizeof(ev));

    /* During an active attack, a B press cancels cooperatively right away. */
    if(s_state == KEYS_STATE_RECOVER && ev.event == BUTTON_SINGLE_CLICK &&
       ev.button == BTN_B)
    {
        s_cancel_requested = true;
    }

    menu_nfc_keys_button_msg_t qmsg = {.button = ev.button, .event = ev.event};
    (void)xQueueSend(s_btn_q, &qmsg, 0);
}

static void menu_nfc_keys_exit_(void)
{
    TaskHandle_t current_task = xTaskGetCurrentTaskHandle();

    menu_nfc_keys_stop_rf_();
    s_active = false;
    s_exit_requested = false;

    if(s_ui_task != NULL)
    {
        if(s_ui_task != current_task)
        {
            TaskHandle_t t = s_ui_task;
            s_ui_task = NULL;
            vTaskDelete(t);
        }
        else
        {
            s_ui_task = NULL;
        }
    }

    if(s_btn_q != NULL)
    {
        QueueHandle_t q = s_btn_q;
        s_btn_q = NULL;
        vQueueDelete(q);
    }

    if(s_buttons_subscribed)
    {
        (void)poom_sbus_unsubscribe_cb("input/button",
                                       menu_nfc_keys_button_cb_, s_sbus_user);
        s_buttons_subscribed = false;
    }

    const uint8_t token = 1;
    (void)poom_sbus_publish(POOM_MENU_RESUME_TOPIC, &token, sizeof(token), 0);
}

static void menu_nfc_keys_ui_task_(void* arg)
{
    (void)arg;

    s_state = KEYS_STATE_IDLE;
    menu_nfc_keys_draw_idle_();

    while(s_active && !s_exit_requested)
    {
        menu_nfc_keys_button_msg_t msg;
        if(s_btn_q == NULL ||
           xQueueReceive(s_btn_q, &msg,
                         pdMS_TO_TICKS(MENU_NFC_KEYS_REFRESH_MS)) != pdTRUE)
        {
            continue;
        }
        if(msg.event != BUTTON_SINGLE_CLICK)
        {
            continue;
        }

        if(s_state == KEYS_STATE_IDLE)
        {
            if(msg.button == BTN_A)
            {
                s_state = KEYS_STATE_RECOVER;
                menu_nfc_keys_recover_();
                menu_nfc_keys_draw_done_();
            }
            else if(msg.button == BTN_B)
            {
                s_exit_requested = true;
            }
        }
        else if(s_state == KEYS_STATE_DONE)
        {
            if(msg.button == BTN_A)
            {
                menu_nfc_keys_dump_();
                menu_nfc_keys_draw_done_();
            }
            else if(msg.button == BTN_RIGHT)
            {
                if(s_unlocked > 0U)
                {
                    s_view_block = 0U;
                    s_state = KEYS_STATE_VIEW;
                    menu_nfc_keys_draw_view_();
                }
            }
            else if(msg.button == BTN_DOWN)
            {
                if(s_unlocked > 0U)
                {
                    menu_nfc_keys_save_keys_();
                    menu_nfc_keys_draw_done_();
                }
            }
            else if(msg.button == BTN_UP)
            {
                menu_nfc_keys_stop_rf_();
                s_state = KEYS_STATE_RECOVER;
                menu_nfc_keys_recover_();
                menu_nfc_keys_draw_done_();
            }
            else if(msg.button == BTN_B)
            {
                s_exit_requested = true;
            }
        }
        else if(s_state == KEYS_STATE_VIEW)
        {
            const uint16_t maxb = poom_mifare_classic_get_max_block();
            if(msg.button == BTN_DOWN)
            {
                if((uint16_t)(s_view_block + 1U) < maxb)
                {
                    s_view_block++;
                }
                menu_nfc_keys_draw_view_();
            }
            else if(msg.button == BTN_UP)
            {
                if(s_view_block > 0U)
                {
                    s_view_block--;
                }
                menu_nfc_keys_draw_view_();
            }
            else if(msg.button == BTN_B)
            {
                s_state = KEYS_STATE_DONE;
                menu_nfc_keys_draw_done_();
            }
        }
    }

    menu_nfc_keys_exit_();
    vTaskDelete(NULL);
}

void menu_nfc_keys_show(void)
{
    s_active = true;
    s_exit_requested = false;
    s_cancel_requested = false;
    s_rf_live = false;
    s_state = KEYS_STATE_IDLE;
    (void)snprintf(s_status, sizeof(s_status), "READY");
    menu_nfc_keys_reset_model_();

    if(!s_buttons_subscribed)
    {
        if(poom_sbus_subscribe_cb("input/button", menu_nfc_keys_button_cb_,
                                  s_sbus_user))
        {
            s_buttons_subscribed = true;
        }
        else
        {
            s_active = false;
            const uint8_t token = 1;
            (void)poom_sbus_publish(POOM_MENU_RESUME_TOPIC, &token,
                                    sizeof(token), 0);
            return;
        }
    }

    if(s_btn_q == NULL)
    {
        s_btn_q = xQueueCreate(8, sizeof(menu_nfc_keys_button_msg_t));
        if(s_btn_q == NULL)
        {
            s_active = false;
            if(s_buttons_subscribed)
            {
                (void)poom_sbus_unsubscribe_cb(
                    "input/button", menu_nfc_keys_button_cb_, s_sbus_user);
                s_buttons_subscribed = false;
            }
            const uint8_t token = 1;
            (void)poom_sbus_publish(POOM_MENU_RESUME_TOPIC, &token,
                                    sizeof(token), 0);
            return;
        }
    }

    if(s_ui_task == NULL)
    {
        (void)xTaskCreate(menu_nfc_keys_ui_task_, "menu_nfc_keys",
                          MENU_NFC_KEYS_STACK, NULL, MENU_NFC_KEYS_PRIO,
                          &s_ui_task);
    }
}
