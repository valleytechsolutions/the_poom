// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * ZEN > NFC > DICT: on-device MIFARE key-dictionary manager.
 *
 * Browse SD .dic files, load one as the active dictionary (consumed by the
 * KEYS scene and MIFARE read), export the built-in defaults to an editable
 * .dic, and clear the active set. Built on the public poom_nfc_dict API.
 */

#include "menu_nfc_dict_ui.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Arduboy2.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "input_events.h"
#include "poom_nfc_dict.h"
#include "poom_sbus.h"

#define POOM_MENU_RESUME_TOPIC "poom/menu/resume"

#define MENU_NFC_DICT_REFRESH_MS (150U)
#define MENU_NFC_DICT_STACK (3584U)
#define MENU_NFC_DICT_PRIO (4U)

#define MENU_NFC_DICT_MAX_FILES (24U)
#define MENU_NFC_DICT_NAME_LEN (40U)
#define MENU_NFC_DICT_VISIBLE_ROWS (4U)

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
#ifndef BTN_UP
#define BTN_UP (4U)
#endif
#ifndef BTN_DOWN
#define BTN_DOWN (5U)
#endif
#ifndef BUTTON_SINGLE_CLICK
#define BUTTON_SINGLE_CLICK (4U)
#endif

typedef struct
{
    uint8_t button;
    uint8_t event;
} menu_nfc_dict_button_msg_t;

static bool s_active = false;
static bool s_buttons_subscribed = false;
static bool s_exit_requested = false;
static TaskHandle_t s_ui_task = NULL;
static QueueHandle_t s_btn_q = NULL;
static char s_sbus_user[] = "menu_nfc_dict";

/* The first row is a synthetic "Export built-in defaults" action; SD files
 * follow. */
static char s_files[MENU_NFC_DICT_MAX_FILES][MENU_NFC_DICT_NAME_LEN];
static uint8_t s_file_count = 0U;
static uint8_t s_sel = 0U;    /* 0 = export action, 1.. = file index + 1 */
static uint8_t s_top = 0U;    /* scroll window top (in row units)          */
static char s_status[22] = "";

static void menu_nfc_dict_button_cb_(const poom_sbus_msg_t* msg, void* user_ctx);
static void menu_nfc_dict_ui_task_(void* arg);

/* ---- SD listing ---------------------------------------------------------- */

static bool menu_nfc_dict_collect_cb_(const char* filename, size_t size_bytes,
                                      void* user_ctx)
{
    (void)size_bytes;
    (void)user_ctx;
    if(s_file_count >= MENU_NFC_DICT_MAX_FILES)
    {
        return false; /* stop early */
    }
    (void)snprintf(s_files[s_file_count], MENU_NFC_DICT_NAME_LEN, "%s",
                   filename ? filename : "?");
    s_file_count++;
    return true;
}

static void menu_nfc_dict_refresh_files_(void)
{
    s_file_count = 0U;
    (void)poom_nfc_dict_list_files(menu_nfc_dict_collect_cb_, NULL);
}

/* Total selectable rows: the export action + the files. */
static uint8_t menu_nfc_dict_row_count_(void)
{
    return (uint8_t)(1U + s_file_count);
}

/* ---- drawing ------------------------------------------------------------- */

static void menu_nfc_dict_draw_(void)
{
    char line[MENU_NFC_DICT_NAME_LEN + 8U];
    const uint8_t rows = menu_nfc_dict_row_count_();

    poom_arduboy_clear();
    poom_arduboy_set_text_size(1);
    poom_arduboy_set_cursor(2, 2);
    (void)poom_arduboy_print(F("NFC DICT"));
    /* Active dictionary key count, right-aligned in the header. */
    (void)snprintf(line, sizeof(line), "act:%u",
                   (unsigned)poom_nfc_dict_count(poom_nfc_dict_active()));
    poom_arduboy_set_cursor(78, 2);
    (void)poom_arduboy_print(line);
    poom_arduboy_fill_rect(0, 0, ARDUBOY_WIDTH, HEADER_H, INVERT);

    /* Keep the selection inside the visible window. */
    if(s_sel < s_top)
    {
        s_top = s_sel;
    }
    else if(s_sel >= (uint8_t)(s_top + MENU_NFC_DICT_VISIBLE_ROWS))
    {
        s_top = (uint8_t)(s_sel - MENU_NFC_DICT_VISIBLE_ROWS + 1U);
    }

    for(uint8_t i = 0U; i < MENU_NFC_DICT_VISIBLE_ROWS; i++)
    {
        const uint8_t row = (uint8_t)(s_top + i);
        if(row >= rows)
        {
            break;
        }
        const int16_t y = (int16_t)(14 + i * 10);
        const char marker = (row == s_sel) ? '>' : ' ';
        if(row == 0U)
        {
            (void)snprintf(line, sizeof(line), "%c[Export defaults]", marker);
        }
        else
        {
            (void)snprintf(line, sizeof(line), "%c%.18s", marker,
                           s_files[row - 1U]);
        }
        poom_arduboy_set_cursor(2, y);
        (void)poom_arduboy_print(line);
    }

    if(s_status[0] != '\0')
    {
        poom_arduboy_set_cursor(2, 54);
        (void)poom_arduboy_print(s_status);
    }
    else
    {
        poom_arduboy_set_cursor(0, 54);
        (void)poom_arduboy_print(F("A:LOAD <:CLR B:BK"));
    }
    poom_arduboy_display();
}

static void menu_nfc_dict_draw_busy_(const char* msg)
{
    poom_arduboy_clear();
    poom_arduboy_set_text_size(1);
    poom_arduboy_set_cursor(2, 2);
    (void)poom_arduboy_print(F("NFC DICT"));
    poom_arduboy_fill_rect(0, 0, ARDUBOY_WIDTH, HEADER_H, INVERT);
    poom_arduboy_set_cursor(6, 28);
    (void)poom_arduboy_print(msg ? msg : "Working...");
    poom_arduboy_display();
}

/* ---- actions ------------------------------------------------------------- */

static void menu_nfc_dict_do_export_(void)
{
    size_t written = 0U;
    menu_nfc_dict_draw_busy_("Exporting...");
    const esp_err_t err =
        poom_nfc_dict_write_builtin(POOM_NFC_DICT_DEFAULT_FILE, &written);
    if(err == ESP_OK)
    {
        (void)snprintf(s_status, sizeof(s_status), "WROTE %u keys",
                       (unsigned)written);
        menu_nfc_dict_refresh_files_();
    }
    else
    {
        (void)snprintf(s_status, sizeof(s_status), "EXPORT FAIL");
    }
}

static void menu_nfc_dict_do_load_(uint8_t file_index)
{
    if(file_index >= s_file_count)
    {
        return;
    }
    menu_nfc_dict_draw_busy_("Loading...");
    const esp_err_t err =
        poom_nfc_dict_load_file(s_files[file_index], poom_nfc_dict_active());
    if(err == ESP_OK)
    {
        (void)snprintf(s_status, sizeof(s_status), "LOADED %u",
                       (unsigned)poom_nfc_dict_count(poom_nfc_dict_active()));
    }
    else
    {
        (void)snprintf(s_status, sizeof(s_status), "LOAD FAIL");
    }
}

static void menu_nfc_dict_do_clear_(void)
{
    poom_nfc_dict_clear(poom_nfc_dict_active());
    (void)snprintf(s_status, sizeof(s_status), "ACTIVE CLEARED");
}

/* ---- buttons + task ------------------------------------------------------ */

static void menu_nfc_dict_button_cb_(const poom_sbus_msg_t* msg, void* user_ctx)
{
    (void)user_ctx;
    if(!s_active || msg == NULL || msg->len < sizeof(button_event_msg_t) ||
       s_btn_q == NULL)
    {
        return;
    }
    button_event_msg_t ev;
    memcpy(&ev, msg->data, sizeof(ev));
    menu_nfc_dict_button_msg_t qmsg = {.button = ev.button, .event = ev.event};
    (void)xQueueSend(s_btn_q, &qmsg, 0);
}

static void menu_nfc_dict_exit_(void)
{
    TaskHandle_t current_task = xTaskGetCurrentTaskHandle();

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
                                       menu_nfc_dict_button_cb_, s_sbus_user);
        s_buttons_subscribed = false;
    }

    const uint8_t token = 1;
    (void)poom_sbus_publish(POOM_MENU_RESUME_TOPIC, &token, sizeof(token), 0);
}

static void menu_nfc_dict_ui_task_(void* arg)
{
    (void)arg;

    menu_nfc_dict_refresh_files_();
    menu_nfc_dict_draw_();

    while(s_active && !s_exit_requested)
    {
        menu_nfc_dict_button_msg_t msg;
        if(s_btn_q == NULL ||
           xQueueReceive(s_btn_q, &msg,
                         pdMS_TO_TICKS(MENU_NFC_DICT_REFRESH_MS)) != pdTRUE)
        {
            continue;
        }
        if(msg.event != BUTTON_SINGLE_CLICK)
        {
            continue;
        }

        const uint8_t rows = menu_nfc_dict_row_count_();
        bool redraw = false;

        if(msg.button == BTN_UP)
        {
            if(s_sel > 0U)
            {
                s_sel--;
            }
            s_status[0] = '\0';
            redraw = true;
        }
        else if(msg.button == BTN_DOWN)
        {
            if((uint8_t)(s_sel + 1U) < rows)
            {
                s_sel++;
            }
            s_status[0] = '\0';
            redraw = true;
        }
        else if(msg.button == BTN_A)
        {
            if(s_sel == 0U)
            {
                menu_nfc_dict_do_export_();
            }
            else
            {
                menu_nfc_dict_do_load_((uint8_t)(s_sel - 1U));
            }
            redraw = true;
        }
        else if(msg.button == BTN_LEFT)
        {
            menu_nfc_dict_do_clear_();
            redraw = true;
        }
        else if(msg.button == BTN_B)
        {
            s_exit_requested = true;
        }

        if(s_exit_requested)
        {
            break;
        }
        if(redraw)
        {
            menu_nfc_dict_draw_();
        }
    }

    menu_nfc_dict_exit_();
    vTaskDelete(NULL);
}

void menu_nfc_dict_ui_show(void)
{
    s_active = true;
    s_exit_requested = false;
    s_sel = 0U;
    s_top = 0U;
    s_file_count = 0U;
    s_status[0] = '\0';

    if(!s_buttons_subscribed)
    {
        if(poom_sbus_subscribe_cb("input/button", menu_nfc_dict_button_cb_,
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
        s_btn_q = xQueueCreate(8, sizeof(menu_nfc_dict_button_msg_t));
        if(s_btn_q == NULL)
        {
            s_active = false;
            if(s_buttons_subscribed)
            {
                (void)poom_sbus_unsubscribe_cb(
                    "input/button", menu_nfc_dict_button_cb_, s_sbus_user);
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
        (void)xTaskCreate(menu_nfc_dict_ui_task_, "menu_nfc_dict",
                          MENU_NFC_DICT_STACK, NULL, MENU_NFC_DICT_PRIO,
                          &s_ui_task);
    }
}
