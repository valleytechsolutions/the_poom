set(srcs
    "src/poom_nfc_dict.c"
    "src/poom_nfc_dict_attack.c"
)

idf_component_register(
    SRCS "${srcs}"
    INCLUDE_DIRS "include"
    REQUIRES poom_nfc sd_card
)
