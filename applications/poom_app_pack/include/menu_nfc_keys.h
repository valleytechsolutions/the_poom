// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * ZEN > NFC > KEYS: on-device MIFARE Classic key-recovery scene.
 *
 * Presents the Chameleon Ultra / Flipper-style workflow entirely on the POOM
 * screen: present a card, watch sector keys appear live as the dictionary
 * attack recovers them, then read/dump the card with the recovered keys.
 *
 * Runs on the POOM's existing poom_nfc RF stack (ST25R3916) plus the
 * poom_nfc_dict dictionary attack; no CLI needed.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Launch the MIFARE key-recovery scene.
 *
 * Takes over the display and buttons on its own task. On exit it returns the
 * user to the ZEN > NFC menu (publishes the menu resume token).
 */
void menu_nfc_keys_show(void);

#ifdef __cplusplus
}
#endif
