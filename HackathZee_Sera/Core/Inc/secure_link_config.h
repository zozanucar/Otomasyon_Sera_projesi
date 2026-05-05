#ifndef SECURE_LINK_CONFIG_H
#define SECURE_LINK_CONFIG_H

/*
 * Keep deployment-specific secrets in this file so they are not scattered
 * through the application logic. In production, provision a different copy
 * for each device pair and keep it outside version control where possible.
 */
#define SECURE_LINK_PAIR_SECRET        "HackathZee_1283"
#define SECURE_LINK_WIFI_SSID          "Sera_Agi"
#define SECURE_LINK_WIFI_PASSWORD      "12831283"
#define SECURE_LINK_SENDER_DEVICE_ID   "SERA_TX_01"
#define SECURE_LINK_RECEIVER_DEVICE_ID "SERA_RX_01"

#endif /* SECURE_LINK_CONFIG_H */
