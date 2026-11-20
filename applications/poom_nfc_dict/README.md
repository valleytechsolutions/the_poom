# poom_nfc_dict

SD-card MIFARE key dictionaries and a dictionary attack for the POOM, modeled
on the Chameleon Ultra / Proxmark / Flipper workflow.

The core `poom_nfc` NFC stack (ST25R3916 via `nfcal`, MIFARE Classic Crypto1
auth and key discovery) lives in the upstream `applications/poom_nfc`
submodule. This component sits **in the POOM application repo** and extends
that stack without modifying it, using only `poom_nfc`'s public API:

- loads editable `.dic` key files from the SD card;
- exports the firmware's built-in default dictionary to the SD card;
- runs a full-card dictionary attack that tries the built-in keys **and** the
  loaded SD keys per sector, caching every recovered key so a later
  read/dump reuses it.

## `.dic` file format

Plain text, one 6-byte key per line as **12 hex characters**:

```
# comments start with #, ; or //
FFFFFFFFFFFF
A0A1A2A3A4A5
D3F7D3F7D3F7
```

Spaces inside a line are ignored (`A0 A1 A2 A3 A4 A5` is accepted). Blank and
comment-only lines are skipped. Up to 2048 keys are held in RAM; larger files
are capped with a warning.

## SD layout

```
/sdcard/nfc/dict/
    mf_default_keys.dic     <- firmware defaults, written by nfc-mfc-dict-save
    <your-custom>.dic
```

## CLI commands (poom_cli)

| Command | Purpose |
|---|---|
| `nfc-mfc-dict-save [file.dic]` | Export the built-in default dictionary to the SD card (default `mf_default_keys.dic`). |
| `nfc-mfc-dict-list` | List `.dic` files in `/sdcard/nfc/dict/`. |
| `nfc-mfc-dict-load <file.dic>` | Load a dictionary as the active key set. |
| `nfc-mfc-dict-clear` | Drop the active dictionary (built-ins still apply). |
| `nfc-mfc-dict-attack [-b] [file.dic]` | Dictionary attack over all sectors using built-in + loaded SD keys (`-b` also tries Key B). |

`nfc-mfc-discover` (built-ins only) remains available in the upstream NFC
component. The in-menu MIFARE read runs the built-in discovery and, when a
dictionary is loaded, also tries its keys.

## Typical flow

```
nfc-mfc-dict-save              # first run: write defaults to SD, then edit if wanted
nfc-mfc-dict-load mykeys.dic   # load your own list (or pass it inline below)
nfc-core-start                 # bring up the ST25R RF stack
# present a MIFARE Classic card
nfc-mfc-dict-attack -b         # recover keys, Key A + Key B
nfc-mfc-dump -b                # dump using the recovered keys
```

Intended for authorized testing and development only.
