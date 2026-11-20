// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * ZEN > NFC > DICT: on-device MIFARE key-dictionary manager.
 *
 * Browse the .dic key files on the SD card, load one as the active dictionary
 * (used by the KEYS recovery scene and the MIFARE read), export the firmware's
 * built-in defaults to an editable .dic, and clear the active set -- all on the
 * device, no CLI. Mirrors the Chameleon Ultra / Proxmark dictionary workflow.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Launch the dictionary-manager scene (own task; returns to ZEN on exit).
 */
void menu_nfc_dict_ui_show(void);

#ifdef __cplusplus
}
#endif
