#ifndef SECURE_TELEMETRY_H
#define SECURE_TELEMETRY_H

#include <stddef.h>
#include <stdint.h>

#define SECURE_TELEMETRY_SESSION_ID_SIZE 8U
#define SECURE_TELEMETRY_FRAME_COUNTER_SIZE 4U
#define SECURE_TELEMETRY_IV_SIZE 16U
#define SECURE_TELEMETRY_TAG_SIZE 16U
#define SECURE_TELEMETRY_MAX_PLAINTEXT_LEN 100U
#define SECURE_TELEMETRY_MAX_PACKET_LEN (104U + (SECURE_TELEMETRY_MAX_PLAINTEXT_LEN * 2U))

uint8_t SecureTelemetry_Encode(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *master_secret,
    char *ascii_packet,
    size_t ascii_packet_len);

#endif
