/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_link_config.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef struct
{
  char temperature_c[12];
  char humidity_pct[12];
  char flow_lpm[12];
  char plaintext[128];
  char encrypted_hex[385];
  bool flow_risk;
  bool fan_active;
  bool frost_risk;
  bool valid;
  uint32_t updated_at_ms;
} SensorData_t;

#ifdef HAL_UART_MODULE_ENABLED
typedef struct
{
  const char *command;
  uint16_t wait_ms;
  const char *line1;
  const char *line2;
} EspCommand_t;

typedef struct
{
  uint8_t at_index;
  uint32_t last_action_ms;
  bool init_started;
  bool server_ready;
  bool awaiting_response;
  bool uart_started;
  uint8_t rx_byte;
  volatile uint16_t rx_head;
  volatile uint16_t rx_tail;
  uint8_t rx_fifo[512];
  char text_buffer[768];
  uint16_t text_len;
  char last_hex[385];
  uint32_t last_hex_ms;
  uint32_t last_rx_activity_ms;
  uint32_t last_packet_ms;
  char status_line1[17];
  char status_line2[17];
  uint8_t active_session_id[8];
  uint8_t previous_session_ids[4][8];
  uint32_t highest_frame_counter;
  uint8_t previous_session_count;
  bool session_tracking_valid;
} EspReceiver_t;

typedef enum
{
  ESP_PACKET_INVALID = 0,
  ESP_PACKET_INCOMPLETE,
  ESP_PACKET_READY
} EspPacketProbeResult_t;

typedef struct
{
  bool initialized;
  uint8_t aes_key[16];
  uint8_t aes_round_keys[176];
  uint8_t hmac_key[32];
} EspCryptoContext_t;
#endif

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define USER_LED_GPIO_Port GPIOC
#define USER_LED_Pin GPIO_PIN_13
#define BUZZER_GPIO_Port            GPIOA
#define BUZZER_Pin                  GPIO_PIN_8
#define LCD_BACKLIGHT              0x08U
#define LCD_ENABLE_BIT             0x04U
#define LCD_RS_BIT                 0x01U
#define LCD_LINE_1_ADDR            0x00U
#define LCD_LINE_2_ADDR            0x40U
#define ESP_MASTER_SECRET          SECURE_LINK_PAIR_SECRET
#define ESP_AP_SSID                SECURE_LINK_WIFI_SSID
#define ESP_AP_PASSWORD            SECURE_LINK_WIFI_PASSWORD
#define ESP_WIFI_MODE              "3"
#define ESP_AP_CHANNEL             "1"
#define ESP_AP_ENCRYPTION          "3"
#define ESP_TCP_SERVER_PORT        "80"
#define ESP_AT_RESPONSE_DELAY_MS   500U
#define ESP_BOOT_WAIT_MS           2500U
#define ESP_DUPLICATE_WINDOW_MS    800U
#define ESP_UART_NOISE_KEEP_LEN    192U
#define ESP_PACKET_TIMEOUT_MS      8000U
#define LCD_REFRESH_INTERVAL_MS    250U
#define ALERT_SHOW_MS              3000U
#define ESP_SECURE_PACKET_PREFIX   "ST1:"
#define ESP_SECURE_PACKET_PREFIX_V2 "ST2:"
#define ESP_SECURE_SESSION_ID_LEN  8U
#define ESP_SECURE_FRAME_COUNTER_LEN 4U
#define ESP_SECURE_IV_LEN          16U
#define ESP_SECURE_TAG_LEN         16U
#define ESP_SECURE_MAX_PLAINTEXT   127U
#define ESP_SECURE_PACKET_MAX_LEN  385U

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
I2C_HandleTypeDef hi2c1;

TIM_HandleTypeDef htim1;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
#ifdef HAL_I2C_MODULE_ENABLED
extern I2C_HandleTypeDef hi2c1;

static uint16_t lcd_address = 0U;
static bool lcd_ready = false;
#endif

static SensorData_t sensor_data = {0};
static char alert_line1[17] = "";
static char alert_line2[17] = "";
static uint32_t alert_until_ms = 0U;

#ifdef HAL_UART_MODULE_ENABLED
extern UART_HandleTypeDef huart1;

static EspReceiver_t esp_receiver = {0};
static EspCryptoContext_t esp_crypto = {0};
#endif

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_TIM1_Init(void);
/* USER CODE BEGIN PFP */
#ifdef HAL_I2C_MODULE_ENABLED
static void LCD_Init(void);
static void LCD_ShowMessage(const char *line1, const char *line2);
static void LCD_Service(void);
#endif

static void Buzzer_Service(void);
static void Buzzer_StartAlert(void);
static void Buzzer_StopAlert(void);

#ifdef HAL_UART_MODULE_ENABLED
static void ESP_ServiceStartup(void);
static void ESP_PollUart(void);
static void ESP_StartUartReceive(void);
static void ESP_ProcessTextBuffer(void);
static void ESP_ProcessStartupResponses(void);
static void ESP_ServiceLinkHealth(void);
static void ESP_ForceReinit(const char *line1, const char *line2);
#endif

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#ifdef HAL_I2C_MODULE_ENABLED
static void LCD_ExpanderWrite(uint8_t data)
{
  HAL_I2C_Master_Transmit(&hi2c1, lcd_address, &data, 1U, 100U);
}

static void LCD_PulseEnable(uint8_t data)
{
  LCD_ExpanderWrite(data | LCD_ENABLE_BIT);
  HAL_Delay(1);
  LCD_ExpanderWrite(data & (uint8_t)~LCD_ENABLE_BIT);
  HAL_Delay(1);
}

static void LCD_Write4Bits(uint8_t data)
{
  LCD_ExpanderWrite(data | LCD_BACKLIGHT);
  LCD_PulseEnable(data | LCD_BACKLIGHT);
}

static void LCD_Send(uint8_t value, uint8_t mode)
{
  uint8_t high_nibble = value & 0xF0U;
  uint8_t low_nibble = (uint8_t)((value << 4U) & 0xF0U);

  LCD_Write4Bits(high_nibble | mode);
  LCD_Write4Bits(low_nibble | mode);
}

static void LCD_SendCommand(uint8_t command)
{
  LCD_Send(command, 0U);

  if ((command == 0x01U) || (command == 0x02U))
  {
    HAL_Delay(2);
  }
  else
  {
    HAL_Delay(1);
  }
}

static void LCD_SendData(uint8_t data)
{
  LCD_Send(data, LCD_RS_BIT);
  HAL_Delay(1);
}

static void LCD_SetCursor(uint8_t row, uint8_t col)
{
  uint8_t base_addr = (row == 0U) ? LCD_LINE_1_ADDR : LCD_LINE_2_ADDR;
  LCD_SendCommand((uint8_t)(0x80U | (base_addr + col)));
}

static void LCD_PrintLine(uint8_t row, const char *text)
{
  char buffer[17];
  size_t text_len = strlen(text);

  memset(buffer, ' ', 16U);
  buffer[16] = '\0';

  if (text_len > 16U)
  {
    text_len = 16U;
  }

  memcpy(buffer, text, text_len);

  LCD_SetCursor(row, 0U);
  for (uint8_t i = 0U; i < 16U; i++)
  {
    LCD_SendData((uint8_t)buffer[i]);
  }
}

static void LCD_ShowMessage(const char *line1, const char *line2)
{
  if (!lcd_ready)
  {
    return;
  }

  LCD_PrintLine(0U, line1);
  LCD_PrintLine(1U, line2);
}

static uint16_t LCD_FindAddress(void)
{
  for (uint16_t address = 0x08U; address <= 0x77U; address++)
  {
    if (HAL_I2C_IsDeviceReady(&hi2c1, (uint16_t)(address << 1U), 2U, 100U) == HAL_OK)
    {
      return (uint16_t)(address << 1U);
    }
  }

  return 0U;
}

static void LCD_Init(void)
{
  lcd_address = LCD_FindAddress();
  if (lcd_address == 0U)
  {
    lcd_ready = false;
    return;
  }

  lcd_ready = true;

  HAL_Delay(50);
  LCD_Write4Bits(0x30U);
  HAL_Delay(5);
  LCD_Write4Bits(0x30U);
  HAL_Delay(5);
  LCD_Write4Bits(0x30U);
  HAL_Delay(1);
  LCD_Write4Bits(0x20U);

  LCD_SendCommand(0x28U);
  LCD_SendCommand(0x0CU);
  LCD_SendCommand(0x06U);
  LCD_SendCommand(0x01U);
  LCD_ShowMessage("LCD Baglandi", "ESP Bekleniyor");
}

static void LCD_Service(void)
{
  static uint32_t last_update_ms = 0U;
  char line1[17];
  char line2[17];

  if (!lcd_ready)
  {
    return;
  }

  if ((HAL_GetTick() - last_update_ms) < LCD_REFRESH_INTERVAL_MS)
  {
    return;
  }

  last_update_ms = HAL_GetTick();

  if (!sensor_data.valid)
  {
    #ifdef HAL_UART_MODULE_ENABLED
    LCD_ShowMessage(esp_receiver.status_line1, esp_receiver.status_line2);
    #else
    LCD_ShowMessage("Veri Yok", "UART Kapali");
    #endif
    return;
  }

  if (HAL_GetTick() < alert_until_ms)
  {
    LCD_ShowMessage(alert_line1, alert_line2);
    return;
  }

  snprintf(line1, sizeof(line1), "S:%.5s N:%.5s", sensor_data.temperature_c, sensor_data.humidity_pct);
  snprintf(line2, sizeof(line2), "D:%.8s L/dk", sensor_data.flow_lpm);
  LCD_ShowMessage(line1, line2);
}
#endif

static void Buzzer_Service(void)
{
  if (sensor_data.valid && sensor_data.fan_active)
  {
    Buzzer_StartAlert();
  }
  else
  {
    Buzzer_StopAlert();
  }
}

static void Buzzer_StartAlert(void)
{
#ifdef HAL_TIM_MODULE_ENABLED
  __HAL_TIM_SET_COMPARE(&htim1, TIM_CHANNEL_1, (__HAL_TIM_GET_AUTORELOAD(&htim1) + 1U) / 2U);
  HAL_TIM_PWM_Start(&htim1, TIM_CHANNEL_1);
#else
  HAL_GPIO_WritePin(BUZZER_GPIO_Port, BUZZER_Pin, GPIO_PIN_SET);
#endif
}

static void Buzzer_StopAlert(void)
{
#ifdef HAL_TIM_MODULE_ENABLED
  HAL_TIM_PWM_Stop(&htim1, TIM_CHANNEL_1);
  __HAL_TIM_SET_COMPARE(&htim1, TIM_CHANNEL_1, 0U);
#else
  HAL_GPIO_WritePin(BUZZER_GPIO_Port, BUZZER_Pin, GPIO_PIN_RESET);
#endif
}

#ifdef HAL_UART_MODULE_ENABLED
static const EspCommand_t esp_init_commands[] =
{
  {"AT", ESP_BOOT_WAIT_MS, "ESP Uyaniyor", "AT Gonderildi"},
  {"ATE0", ESP_AT_RESPONSE_DELAY_MS, "Echo Kapat", "ATE0"},
  {"AT+CWMODE=" ESP_WIFI_MODE, ESP_AT_RESPONSE_DELAY_MS, "WiFi Mod", "CWMODE=3"},
  {"AT+CWSAP=\"" ESP_AP_SSID "\",\"" ESP_AP_PASSWORD "\"," ESP_AP_CHANNEL "," ESP_AP_ENCRYPTION, 1600U, "AP Kuruluyor", ESP_AP_SSID},
  {"AT+CIPMUX=1", ESP_AT_RESPONSE_DELAY_MS, "ESP Sunucu", "CIPMUX=1"},
  {"AT+CIPSERVER=1," ESP_TCP_SERVER_PORT, 1000U, "ESP Sunucu", "CIPSERVER=1"}
};

static void ESP_SetStatus(const char *line1, const char *line2)
{
  snprintf(esp_receiver.status_line1, sizeof(esp_receiver.status_line1), "%s", line1);
  snprintf(esp_receiver.status_line2, sizeof(esp_receiver.status_line2), "%s", line2);
}

static void ESP_ForceReinit(const char *line1, const char *line2)
{
  bool uart_started = esp_receiver.uart_started;
  uint8_t rx_byte = esp_receiver.rx_byte;

  memset(esp_receiver.last_hex, 0, sizeof(esp_receiver.last_hex));
  memset(esp_receiver.rx_fifo, 0, sizeof(esp_receiver.rx_fifo));
  memset(esp_receiver.text_buffer, 0, sizeof(esp_receiver.text_buffer));
  memset(esp_receiver.active_session_id, 0, sizeof(esp_receiver.active_session_id));
  memset(esp_receiver.previous_session_ids, 0, sizeof(esp_receiver.previous_session_ids));
  esp_receiver.at_index = 0U;
  esp_receiver.last_action_ms = HAL_GetTick();
  esp_receiver.init_started = false;
  esp_receiver.server_ready = false;
  esp_receiver.awaiting_response = false;
  esp_receiver.uart_started = uart_started;
  esp_receiver.rx_byte = rx_byte;
  esp_receiver.rx_head = 0U;
  esp_receiver.rx_tail = 0U;
  esp_receiver.text_len = 0U;
  esp_receiver.last_hex_ms = 0U;
  esp_receiver.last_rx_activity_ms = 0U;
  esp_receiver.last_packet_ms = 0U;
  esp_receiver.highest_frame_counter = 0U;
  esp_receiver.previous_session_count = 0U;
  esp_receiver.session_tracking_valid = false;

  sensor_data.valid = false;
  ESP_SetStatus(line1, line2);
}

static void ESP_SendCommand(const char *command)
{
  static const char line_end[] = "\r\n";

  HAL_UART_Transmit(&huart1, (uint8_t *)command, (uint16_t)strlen(command), 1000U);
  HAL_UART_Transmit(&huart1, (uint8_t *)line_end, 2U, 100U);
}

static void ESP_ConsumeTextPrefix(uint16_t length)
{
  if (length == 0U)
  {
    return;
  }

  if (length >= esp_receiver.text_len)
  {
    esp_receiver.text_len = 0U;
    esp_receiver.text_buffer[0] = '\0';
    return;
  }

  memmove(esp_receiver.text_buffer,
          &esp_receiver.text_buffer[length],
          esp_receiver.text_len - length);
  esp_receiver.text_len = (uint16_t)(esp_receiver.text_len - length);
  esp_receiver.text_buffer[esp_receiver.text_len] = '\0';
}

static bool ESP_ConsumeThroughToken(const char *token)
{
  char *match;
  uint16_t consume_length;

  if ((token == NULL) || (token[0] == '\0') || (esp_receiver.text_len == 0U))
  {
    return false;
  }

  match = strstr(esp_receiver.text_buffer, token);
  if (match == NULL)
  {
    return false;
  }

  consume_length = (uint16_t)((match - esp_receiver.text_buffer) + strlen(token));
  while ((consume_length < esp_receiver.text_len) &&
         ((esp_receiver.text_buffer[consume_length] == '\r') ||
          (esp_receiver.text_buffer[consume_length] == '\n')))
  {
    consume_length++;
  }

  ESP_ConsumeTextPrefix(consume_length);
  return true;
}

static uint8_t ESP_HexNibble(char value)
{
  if ((value >= '0') && (value <= '9'))
  {
    return (uint8_t)(value - '0');
  }

  value = (char)toupper((unsigned char)value);
  return (uint8_t)(10 + (value - 'A'));
}

static bool ESP_IsHexString(const char *text, size_t length)
{
  for (size_t i = 0U; i < length; i++)
  {
    if (isxdigit((unsigned char)text[i]) == 0)
    {
      return false;
    }
  }

  return true;
}

static bool ESP_ParseHexWord(const char *hex_text, uint16_t *value)
{
  uint16_t parsed = 0U;

  if ((hex_text == NULL) || (value == NULL) || !ESP_IsHexString(hex_text, 4U))
  {
    return false;
  }

  for (size_t i = 0U; i < 4U; i++)
  {
    parsed = (uint16_t)((parsed << 4U) | ESP_HexNibble(hex_text[i]));
  }

  *value = parsed;
  return true;
}

static bool ESP_ParseHexDword(const char *hex_text, uint32_t *value)
{
  uint32_t parsed = 0U;

  if ((hex_text == NULL) || (value == NULL) || !ESP_IsHexString(hex_text, 8U))
  {
    return false;
  }

  for (size_t i = 0U; i < 8U; i++)
  {
    parsed = (parsed << 4U) | ESP_HexNibble(hex_text[i]);
  }

  *value = parsed;
  return true;
}

static bool ESP_HexToBytes(const char *hex_text, size_t hex_length, uint8_t *bytes, size_t bytes_size)
{
  if ((hex_text == NULL) || (bytes == NULL) || ((hex_length % 2U) != 0U) ||
      ((hex_length / 2U) > bytes_size) || !ESP_IsHexString(hex_text, hex_length))
  {
    return false;
  }

  for (size_t i = 0U; i < (hex_length / 2U); i++)
  {
    bytes[i] = (uint8_t)((ESP_HexNibble(hex_text[i * 2U]) << 4U) |
                         ESP_HexNibble(hex_text[(i * 2U) + 1U]));
  }

  return true;
}

static bool ESP_CopyField(const char *payload, const char *label, char terminator, char *out, size_t out_size)
{
  const char *start = strstr(payload, label);
  size_t index = 0U;

  if ((start == NULL) || (out_size == 0U))
  {
    return false;
  }

  start += strlen(label);
  while (*start == ' ')
  {
    start++;
  }

  while ((*start != '\0') && (*start != terminator) && (index + 1U < out_size))
  {
    out[index++] = *start++;
  }

  while ((index > 0U) && (out[index - 1U] == ' '))
  {
    index--;
  }

  out[index] = '\0';
  return index > 0U;
}

static void ESP_ParseOptionalFlagField(const char *payload, const char *label, bool *value)
{
  const char *start;

  if ((payload == NULL) || (label == NULL) || (value == NULL))
  {
    return;
  }

  start = strstr(payload, label);
  if (start == NULL)
  {
    return;
  }

  start += strlen(label);
  while ((*start == ' ') || (*start == '\t'))
  {
    start++;
  }

  if (*start == '1')
  {
    *value = true;
  }
  else if (*start == '0')
  {
    *value = false;
  }
  else if ((toupper((unsigned char)start[0]) == 'O') &&
           (toupper((unsigned char)start[1]) == 'N'))
  {
    *value = true;
  }
  else if ((toupper((unsigned char)start[0]) == 'O') &&
           (toupper((unsigned char)start[1]) == 'F') &&
           (toupper((unsigned char)start[2]) == 'F'))
  {
    *value = false;
  }
}

static bool ESP_ParseSensorPayload(const char *payload, SensorData_t *parsed)
{
  if (!ESP_CopyField(payload, "Sicaklik:", 'C', parsed->temperature_c, sizeof(parsed->temperature_c)))
  {
    return false;
  }

  if (!ESP_CopyField(payload, "Nem:", '%', parsed->humidity_pct, sizeof(parsed->humidity_pct)))
  {
    return false;
  }

  if (!ESP_CopyField(payload, "Debi:", 'L', parsed->flow_lpm, sizeof(parsed->flow_lpm)))
  {
    return false;
  }

  parsed->fan_active = false;
  parsed->frost_risk = false;
  parsed->flow_risk = false;
  ESP_ParseOptionalFlagField(payload, "Fan:", &parsed->fan_active);
  ESP_ParseOptionalFlagField(payload, "Don:", &parsed->frost_risk);
  ESP_ParseOptionalFlagField(payload, "Boru:", &parsed->flow_risk);
  snprintf(parsed->plaintext, sizeof(parsed->plaintext), "%s", payload);
  parsed->updated_at_ms = HAL_GetTick();
  parsed->valid = true;
  return true;
}

static void ESP_SHA256_Transform(uint32_t state[8], const uint8_t block[64])
{
  static const uint32_t k[64] =
  {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
  };
  uint32_t w[64];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;

  for (size_t i = 0U; i < 16U; i++)
  {
    w[i] = ((uint32_t)block[i * 4U] << 24U) |
           ((uint32_t)block[(i * 4U) + 1U] << 16U) |
           ((uint32_t)block[(i * 4U) + 2U] << 8U) |
           (uint32_t)block[(i * 4U) + 3U];
  }

  for (size_t i = 16U; i < 64U; i++)
  {
    uint32_t s0 = ((w[i - 15U] >> 7U) | (w[i - 15U] << 25U)) ^
                  ((w[i - 15U] >> 18U) | (w[i - 15U] << 14U)) ^
                  (w[i - 15U] >> 3U);
    uint32_t s1 = ((w[i - 2U] >> 17U) | (w[i - 2U] << 15U)) ^
                  ((w[i - 2U] >> 19U) | (w[i - 2U] << 13U)) ^
                  (w[i - 2U] >> 10U);

    w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
  }

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  for (size_t i = 0U; i < 64U; i++)
  {
    uint32_t s1 = ((e >> 6U) | (e << 26U)) ^
                  ((e >> 11U) | (e << 21U)) ^
                  ((e >> 25U) | (e << 7U));
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + s1 + ch + k[i] + w[i];
    uint32_t s0 = ((a >> 2U) | (a << 30U)) ^
                  ((a >> 13U) | (a << 19U)) ^
                  ((a >> 22U) | (a << 10U));
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

typedef struct
{
  uint32_t state[8];
  uint8_t buffer[64];
  uint64_t bit_length;
  size_t buffer_length;
} EspSha256Context_t;

static void ESP_SHA256_Init(EspSha256Context_t *ctx)
{
  ctx->state[0] = 0x6a09e667UL;
  ctx->state[1] = 0xbb67ae85UL;
  ctx->state[2] = 0x3c6ef372UL;
  ctx->state[3] = 0xa54ff53aUL;
  ctx->state[4] = 0x510e527fUL;
  ctx->state[5] = 0x9b05688cUL;
  ctx->state[6] = 0x1f83d9abUL;
  ctx->state[7] = 0x5be0cd19UL;
  ctx->bit_length = 0U;
  ctx->buffer_length = 0U;
}

static void ESP_SHA256_Update(EspSha256Context_t *ctx, const uint8_t *data, size_t length)
{
  for (size_t i = 0U; i < length; i++)
  {
    ctx->buffer[ctx->buffer_length++] = data[i];

    if (ctx->buffer_length == sizeof(ctx->buffer))
    {
      ESP_SHA256_Transform(ctx->state, ctx->buffer);
      ctx->bit_length += 512U;
      ctx->buffer_length = 0U;
    }
  }
}

static void ESP_SHA256_Final(EspSha256Context_t *ctx, uint8_t hash[32])
{
  size_t index = ctx->buffer_length;

  ctx->bit_length += (uint64_t)index * 8ULL;
  ctx->buffer[index++] = 0x80U;

  if (index > 56U)
  {
    while (index < 64U)
    {
      ctx->buffer[index++] = 0x00U;
    }

    ESP_SHA256_Transform(ctx->state, ctx->buffer);
    index = 0U;
  }

  while (index < 56U)
  {
    ctx->buffer[index++] = 0x00U;
  }

  for (size_t i = 0U; i < 8U; i++)
  {
    ctx->buffer[56U + i] = (uint8_t)(ctx->bit_length >> ((7U - i) * 8U));
  }

  ESP_SHA256_Transform(ctx->state, ctx->buffer);

  for (size_t i = 0U; i < 8U; i++)
  {
    hash[i * 4U] = (uint8_t)(ctx->state[i] >> 24U);
    hash[(i * 4U) + 1U] = (uint8_t)(ctx->state[i] >> 16U);
    hash[(i * 4U) + 2U] = (uint8_t)(ctx->state[i] >> 8U);
    hash[(i * 4U) + 3U] = (uint8_t)ctx->state[i];
  }
}

static void ESP_SHA256_Data(const uint8_t *data, size_t length, uint8_t hash[32])
{
  EspSha256Context_t ctx;

  ESP_SHA256_Init(&ctx);
  ESP_SHA256_Update(&ctx, data, length);
  ESP_SHA256_Final(&ctx, hash);
}

static void ESP_SHA256_DataPair(const uint8_t *data1, size_t length1,
                                const uint8_t *data2, size_t length2,
                                uint8_t hash[32])
{
  EspSha256Context_t ctx;

  ESP_SHA256_Init(&ctx);
  ESP_SHA256_Update(&ctx, data1, length1);
  ESP_SHA256_Update(&ctx, data2, length2);
  ESP_SHA256_Final(&ctx, hash);
}

static void ESP_SHA256_DataTriple(const uint8_t *data1, size_t length1,
                                  const uint8_t *data2, size_t length2,
                                  const uint8_t *data3, size_t length3,
                                  uint8_t hash[32])
{
  EspSha256Context_t ctx;

  ESP_SHA256_Init(&ctx);
  ESP_SHA256_Update(&ctx, data1, length1);
  ESP_SHA256_Update(&ctx, data2, length2);
  ESP_SHA256_Update(&ctx, data3, length3);
  ESP_SHA256_Final(&ctx, hash);
}

static uint8_t ESP_AES_Multiply(uint8_t value, uint8_t factor)
{
  uint8_t result = 0U;
  uint8_t current = value;

  while (factor != 0U)
  {
    if ((factor & 1U) != 0U)
    {
      result ^= current;
    }

    if ((current & 0x80U) != 0U)
    {
      current = (uint8_t)((current << 1U) ^ 0x1BU);
    }
    else
    {
      current <<= 1U;
    }

    factor >>= 1U;
  }

  return result;
}

static uint8_t ESP_AES_Power(uint8_t value, uint8_t exponent)
{
  uint8_t result = 1U;

  while (exponent != 0U)
  {
    if ((exponent & 1U) != 0U)
    {
      result = ESP_AES_Multiply(result, value);
    }

    value = ESP_AES_Multiply(value, value);
    exponent >>= 1U;
  }

  return result;
}

static uint8_t ESP_AES_SubByte(uint8_t value)
{
  uint8_t inverse = (value == 0U) ? 0U : ESP_AES_Power(value, 254U);
  uint8_t result = (uint8_t)(inverse ^
                             ((inverse << 1U) | (inverse >> 7U)) ^
                             ((inverse << 2U) | (inverse >> 6U)) ^
                             ((inverse << 3U) | (inverse >> 5U)) ^
                             ((inverse << 4U) | (inverse >> 4U)) ^
                             0x63U);

  return result;
}

static void ESP_AES_KeyExpansion(const uint8_t key[16], uint8_t round_keys[176])
{
  static const uint8_t rcon[10] = {0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U, 0x1BU, 0x36U};
  uint8_t temp[4];
  size_t generated = 16U;
  size_t rcon_index = 0U;

  memcpy(round_keys, key, 16U);

  while (generated < 176U)
  {
    memcpy(temp, &round_keys[generated - 4U], sizeof(temp));

    if ((generated % 16U) == 0U)
    {
      uint8_t swap = temp[0];

      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = swap;

      temp[0] = ESP_AES_SubByte(temp[0]);
      temp[1] = ESP_AES_SubByte(temp[1]);
      temp[2] = ESP_AES_SubByte(temp[2]);
      temp[3] = ESP_AES_SubByte(temp[3]);
      temp[0] ^= rcon[rcon_index++];
    }

    for (size_t i = 0U; i < 4U; i++)
    {
      round_keys[generated] = (uint8_t)(round_keys[generated - 16U] ^ temp[i]);
      generated++;
    }
  }
}

static void ESP_AES_AddRoundKey(uint8_t state[16], const uint8_t *round_key)
{
  for (size_t i = 0U; i < 16U; i++)
  {
    state[i] ^= round_key[i];
  }
}

static void ESP_AES_SubBytes(uint8_t state[16])
{
  for (size_t i = 0U; i < 16U; i++)
  {
    state[i] = ESP_AES_SubByte(state[i]);
  }
}

static void ESP_AES_ShiftRows(uint8_t state[16])
{
  uint8_t temp[16];

  memcpy(temp, state, sizeof(temp));
  state[0] = temp[0];
  state[1] = temp[5];
  state[2] = temp[10];
  state[3] = temp[15];
  state[4] = temp[4];
  state[5] = temp[9];
  state[6] = temp[14];
  state[7] = temp[3];
  state[8] = temp[8];
  state[9] = temp[13];
  state[10] = temp[2];
  state[11] = temp[7];
  state[12] = temp[12];
  state[13] = temp[1];
  state[14] = temp[6];
  state[15] = temp[11];
}

static void ESP_AES_MixColumns(uint8_t state[16])
{
  for (size_t column = 0U; column < 4U; column++)
  {
    size_t index = column * 4U;
    uint8_t s0 = state[index];
    uint8_t s1 = state[index + 1U];
    uint8_t s2 = state[index + 2U];
    uint8_t s3 = state[index + 3U];

    state[index] = (uint8_t)(ESP_AES_Multiply(s0, 2U) ^ ESP_AES_Multiply(s1, 3U) ^ s2 ^ s3);
    state[index + 1U] = (uint8_t)(s0 ^ ESP_AES_Multiply(s1, 2U) ^ ESP_AES_Multiply(s2, 3U) ^ s3);
    state[index + 2U] = (uint8_t)(s0 ^ s1 ^ ESP_AES_Multiply(s2, 2U) ^ ESP_AES_Multiply(s3, 3U));
    state[index + 3U] = (uint8_t)(ESP_AES_Multiply(s0, 3U) ^ s1 ^ s2 ^ ESP_AES_Multiply(s3, 2U));
  }
}

static void ESP_AES_EncryptBlock(const uint8_t input[16], const uint8_t round_keys[176], uint8_t output[16])
{
  uint8_t state[16];

  memcpy(state, input, sizeof(state));
  ESP_AES_AddRoundKey(state, round_keys);

  for (size_t round = 1U; round < 10U; round++)
  {
    ESP_AES_SubBytes(state);
    ESP_AES_ShiftRows(state);
    ESP_AES_MixColumns(state);
    ESP_AES_AddRoundKey(state, &round_keys[round * 16U]);
  }

  ESP_AES_SubBytes(state);
  ESP_AES_ShiftRows(state);
  ESP_AES_AddRoundKey(state, &round_keys[160U]);
  memcpy(output, state, sizeof(state));
}

static void ESP_AES_CTR_Transform(uint8_t *data, size_t length, const uint8_t round_keys[176], const uint8_t iv[16])
{
  uint8_t counter[16];
  uint8_t stream_block[16];
  size_t offset = 0U;

  memcpy(counter, iv, sizeof(counter));

  while (offset < length)
  {
    ESP_AES_EncryptBlock(counter, round_keys, stream_block);

    for (size_t i = 0U; (i < 16U) && (offset < length); i++, offset++)
    {
      data[offset] ^= stream_block[i];
    }

    for (int32_t i = 15; i >= 0; i--)
    {
      counter[i]++;
      if (counter[i] != 0U)
      {
        break;
      }
    }
  }
}

static void ESP_HMAC_SHA256(const uint8_t *key, size_t key_length,
                            const uint8_t *data, size_t data_length,
                            uint8_t digest[32])
{
  uint8_t key_block[64];
  uint8_t inner_hash[32];
  uint8_t inner_pad[64];
  uint8_t outer_pad[64];

  memset(key_block, 0, sizeof(key_block));

  if (key_length > sizeof(key_block))
  {
    ESP_SHA256_Data(key, key_length, key_block);
  }
  else
  {
    memcpy(key_block, key, key_length);
  }

  for (size_t i = 0U; i < sizeof(key_block); i++)
  {
    inner_pad[i] = (uint8_t)(key_block[i] ^ 0x36U);
    outer_pad[i] = (uint8_t)(key_block[i] ^ 0x5CU);
  }

  ESP_SHA256_DataPair(inner_pad, sizeof(inner_pad), data, data_length, inner_hash);
  ESP_SHA256_DataPair(outer_pad, sizeof(outer_pad), inner_hash, sizeof(inner_hash), digest);
}

static bool ESP_SecureEquals(const uint8_t *lhs, const uint8_t *rhs, size_t length)
{
  uint8_t diff = 0U;

  for (size_t i = 0U; i < length; i++)
  {
    diff |= (uint8_t)(lhs[i] ^ rhs[i]);
  }

  return diff == 0U;
}

static void ESP_StoreBe32(uint32_t value, uint8_t output[4])
{
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

static void ESP_EnsureCryptoContext(void)
{
  static const uint8_t aes_label[] = "AES-128-CTR";
  static const uint8_t hmac_label[] = "HMAC-SHA256";
  static const uint8_t context_label[] = "SECURE-LINK-CONTEXT";
  static const uint8_t master_secret[] = ESP_MASTER_SECRET;
  uint8_t hash[32];
  uint8_t context_hash[32];

  if (esp_crypto.initialized)
  {
    return;
  }

  ESP_SHA256_DataTriple(
      context_label,
      sizeof(context_label) - 1U,
      (const uint8_t *)SECURE_LINK_SENDER_DEVICE_ID,
      strlen(SECURE_LINK_SENDER_DEVICE_ID),
      (const uint8_t *)SECURE_LINK_RECEIVER_DEVICE_ID,
      strlen(SECURE_LINK_RECEIVER_DEVICE_ID),
      context_hash);

  ESP_SHA256_DataTriple(aes_label, sizeof(aes_label) - 1U,
                        context_hash, sizeof(context_hash),
                        master_secret, sizeof(master_secret) - 1U,
                        hash);
  memcpy(esp_crypto.aes_key, hash, sizeof(esp_crypto.aes_key));
  ESP_AES_KeyExpansion(esp_crypto.aes_key, esp_crypto.aes_round_keys);

  ESP_SHA256_DataTriple(hmac_label, sizeof(hmac_label) - 1U,
                        context_hash, sizeof(context_hash),
                        master_secret, sizeof(master_secret) - 1U,
                        hash);
  memcpy(esp_crypto.hmac_key, hash, sizeof(esp_crypto.hmac_key));
  esp_crypto.initialized = true;
}

static bool ESP_IsKnownPreviousSession(const uint8_t session_id[ESP_SECURE_SESSION_ID_LEN])
{
  for (uint8_t i = 0U; i < esp_receiver.previous_session_count; i++)
  {
    if (memcmp(esp_receiver.previous_session_ids[i], session_id, ESP_SECURE_SESSION_ID_LEN) == 0)
    {
      return true;
    }
  }

  return false;
}

static void ESP_RememberPreviousSession(const uint8_t session_id[ESP_SECURE_SESSION_ID_LEN])
{
  uint8_t slot = 0U;

  if (ESP_IsKnownPreviousSession(session_id))
  {
    return;
  }

  if (esp_receiver.previous_session_count < 4U)
  {
    slot = esp_receiver.previous_session_count++;
  }
  else
  {
    memmove(
        esp_receiver.previous_session_ids,
        &esp_receiver.previous_session_ids[1],
        sizeof(esp_receiver.previous_session_ids[0]) * 3U);
    slot = 3U;
  }

  memcpy(esp_receiver.previous_session_ids[slot], session_id, ESP_SECURE_SESSION_ID_LEN);
}

static bool ESP_AcceptReplayWindow(
    const uint8_t session_id[ESP_SECURE_SESSION_ID_LEN],
    uint32_t frame_counter)
{
  if (!esp_receiver.session_tracking_valid)
  {
    memcpy(esp_receiver.active_session_id, session_id, ESP_SECURE_SESSION_ID_LEN);
    esp_receiver.highest_frame_counter = frame_counter;
    esp_receiver.session_tracking_valid = true;
    return true;
  }

  if (memcmp(esp_receiver.active_session_id, session_id, ESP_SECURE_SESSION_ID_LEN) == 0)
  {
    if (frame_counter <= esp_receiver.highest_frame_counter)
    {
      return false;
    }

    esp_receiver.highest_frame_counter = frame_counter;
    return true;
  }

  if (ESP_IsKnownPreviousSession(session_id))
  {
    return false;
  }

  ESP_RememberPreviousSession(esp_receiver.active_session_id);
  memcpy(esp_receiver.active_session_id, session_id, ESP_SECURE_SESSION_ID_LEN);
  esp_receiver.highest_frame_counter = frame_counter;
  esp_receiver.session_tracking_valid = true;
  return true;
}

static bool ESP_DecryptSecurePayloadV1(const char *packet, char *plaintext, size_t plaintext_size)
{
  uint16_t plaintext_length = 0U;
  size_t cipher_hex_length;
  uint8_t iv[ESP_SECURE_IV_LEN];
  uint8_t ciphertext[ESP_SECURE_MAX_PLAINTEXT];
  uint8_t auth_buffer[ESP_SECURE_IV_LEN + ESP_SECURE_MAX_PLAINTEXT];
  uint8_t expected_tag[32];
  uint8_t received_tag[ESP_SECURE_TAG_LEN];

  if ((packet == NULL) || (plaintext == NULL) || (plaintext_size == 0U) ||
      (memcmp(packet, ESP_SECURE_PACKET_PREFIX, 4U) != 0))
  {
    return false;
  }

  if (!ESP_ParseHexWord(&packet[4], &plaintext_length) ||
      (plaintext_length == 0U) ||
      (plaintext_length > ESP_SECURE_MAX_PLAINTEXT) ||
      ((plaintext_length + 1U) > plaintext_size) ||
      (packet[8] != ':') ||
      (packet[41] != ':'))
  {
    return false;
  }

  cipher_hex_length = (size_t)plaintext_length * 2U;

  if (packet[42U + cipher_hex_length] != ':')
  {
    return false;
  }

  if (!ESP_HexToBytes(&packet[9], 32U, iv, sizeof(iv)) ||
      !ESP_HexToBytes(&packet[42], cipher_hex_length, ciphertext, sizeof(ciphertext)) ||
      !ESP_HexToBytes(&packet[43U + cipher_hex_length], 32U, received_tag, sizeof(received_tag)))
  {
    return false;
  }

  memcpy(auth_buffer, iv, sizeof(iv));
  memcpy(&auth_buffer[sizeof(iv)], ciphertext, plaintext_length);

  ESP_EnsureCryptoContext();
  ESP_HMAC_SHA256(esp_crypto.hmac_key, sizeof(esp_crypto.hmac_key),
                  auth_buffer, sizeof(iv) + plaintext_length,
                  expected_tag);

  if (!ESP_SecureEquals(received_tag, expected_tag, ESP_SECURE_TAG_LEN))
  {
    return false;
  }

  ESP_AES_CTR_Transform(ciphertext, plaintext_length, esp_crypto.aes_round_keys, iv);
  memcpy(plaintext, ciphertext, plaintext_length);
  plaintext[plaintext_length] = '\0';
  return true;
}

static bool ESP_DecryptSecurePayloadV2(
    const char *packet,
    char *plaintext,
    size_t plaintext_size,
    uint8_t session_id[ESP_SECURE_SESSION_ID_LEN],
    uint32_t *frame_counter)
{
  uint16_t plaintext_length = 0U;
  size_t cipher_hex_length;
  uint8_t frame_counter_bytes[ESP_SECURE_FRAME_COUNTER_LEN];
  uint8_t iv[ESP_SECURE_IV_LEN];
  uint8_t ciphertext[ESP_SECURE_MAX_PLAINTEXT];
  uint8_t auth_buffer[
      ESP_SECURE_SESSION_ID_LEN +
      ESP_SECURE_FRAME_COUNTER_LEN +
      ESP_SECURE_IV_LEN +
      ESP_SECURE_MAX_PLAINTEXT];
  uint8_t expected_tag[32];
  uint8_t received_tag[ESP_SECURE_TAG_LEN];

  if ((packet == NULL) || (plaintext == NULL) || (plaintext_size == 0U) ||
      (session_id == NULL) || (frame_counter == NULL) ||
      (memcmp(packet, ESP_SECURE_PACKET_PREFIX_V2, 4U) != 0))
  {
    return false;
  }

  if (!ESP_ParseHexWord(&packet[4], &plaintext_length) ||
      (plaintext_length == 0U) ||
      (plaintext_length > ESP_SECURE_MAX_PLAINTEXT) ||
      ((plaintext_length + 1U) > plaintext_size) ||
      (packet[8] != ':') ||
      (packet[25] != ':') ||
      (packet[34] != ':') ||
      (packet[67] != ':'))
  {
    return false;
  }

  cipher_hex_length = (size_t)plaintext_length * 2U;
  if (packet[68U + cipher_hex_length] != ':')
  {
    return false;
  }

  if (!ESP_HexToBytes(&packet[9], 16U, session_id, ESP_SECURE_SESSION_ID_LEN) ||
      !ESP_ParseHexDword(&packet[26], frame_counter) ||
      !ESP_HexToBytes(&packet[35], 32U, iv, sizeof(iv)) ||
      !ESP_HexToBytes(&packet[68], cipher_hex_length, ciphertext, sizeof(ciphertext)) ||
      !ESP_HexToBytes(&packet[69U + cipher_hex_length], 32U, received_tag, sizeof(received_tag)))
  {
    return false;
  }

  ESP_StoreBe32(*frame_counter, frame_counter_bytes);
  memcpy(auth_buffer, session_id, ESP_SECURE_SESSION_ID_LEN);
  memcpy(&auth_buffer[ESP_SECURE_SESSION_ID_LEN], frame_counter_bytes, sizeof(frame_counter_bytes));
  memcpy(&auth_buffer[ESP_SECURE_SESSION_ID_LEN + sizeof(frame_counter_bytes)], iv, sizeof(iv));
  memcpy(&auth_buffer[ESP_SECURE_SESSION_ID_LEN + sizeof(frame_counter_bytes) + sizeof(iv)], ciphertext, plaintext_length);

  ESP_EnsureCryptoContext();
  ESP_HMAC_SHA256(
      esp_crypto.hmac_key,
      sizeof(esp_crypto.hmac_key),
      auth_buffer,
      ESP_SECURE_SESSION_ID_LEN + sizeof(frame_counter_bytes) + sizeof(iv) + plaintext_length,
      expected_tag);

  if (!ESP_SecureEquals(received_tag, expected_tag, ESP_SECURE_TAG_LEN))
  {
    return false;
  }

  ESP_AES_CTR_Transform(ciphertext, plaintext_length, esp_crypto.aes_round_keys, iv);
  memcpy(plaintext, ciphertext, plaintext_length);
  plaintext[plaintext_length] = '\0';
  return true;
}

static EspPacketProbeResult_t ESP_ProbeSecurePacket(const char *start, size_t available, size_t *packet_length)
{
  uint16_t plaintext_length = 0U;
  size_t full_length;
  size_t cipher_hex_length;

  if ((start == NULL) || (packet_length == NULL))
  {
    return ESP_PACKET_INVALID;
  }

  if (memcmp(start, ESP_SECURE_PACKET_PREFIX_V2, 4U) == 0)
  {
    if (available < 68U)
    {
      return ESP_PACKET_INCOMPLETE;
    }

    if (!ESP_ParseHexWord(&start[4], &plaintext_length) ||
        (plaintext_length == 0U) ||
        (plaintext_length > ESP_SECURE_MAX_PLAINTEXT) ||
        (start[8] != ':') ||
        (start[25] != ':') ||
        (start[34] != ':') ||
        (start[67] != ':'))
    {
      return ESP_PACKET_INVALID;
    }

    cipher_hex_length = (size_t)plaintext_length * 2U;
    full_length = 101U + cipher_hex_length;

    if (full_length >= ESP_SECURE_PACKET_MAX_LEN)
    {
      return ESP_PACKET_INVALID;
    }

    if (available < full_length)
    {
      return ESP_PACKET_INCOMPLETE;
    }

    if ((start[68U + cipher_hex_length] != ':') ||
        !ESP_IsHexString(&start[9], 16U) ||
        !ESP_IsHexString(&start[26], 8U) ||
        !ESP_IsHexString(&start[35], 32U) ||
        !ESP_IsHexString(&start[68], cipher_hex_length) ||
        !ESP_IsHexString(&start[69U + cipher_hex_length], 32U))
    {
      return ESP_PACKET_INVALID;
    }

    *packet_length = full_length;
    return ESP_PACKET_READY;
  }

  if (available < 42U)
  {
    return ESP_PACKET_INCOMPLETE;
  }

  if ((memcmp(start, ESP_SECURE_PACKET_PREFIX, 4U) != 0) ||
      !ESP_ParseHexWord(&start[4], &plaintext_length) ||
      (plaintext_length == 0U) ||
      (plaintext_length > ESP_SECURE_MAX_PLAINTEXT) ||
      (start[8] != ':') ||
      (start[41] != ':'))
  {
    return ESP_PACKET_INVALID;
  }

  cipher_hex_length = (size_t)plaintext_length * 2U;
  full_length = 75U + cipher_hex_length;

  if (full_length >= ESP_SECURE_PACKET_MAX_LEN)
  {
    return ESP_PACKET_INVALID;
  }

  if (available < full_length)
  {
    return ESP_PACKET_INCOMPLETE;
  }

  if ((start[42U + cipher_hex_length] != ':') ||
      !ESP_IsHexString(&start[9], 32U) ||
      !ESP_IsHexString(&start[42], cipher_hex_length) ||
      !ESP_IsHexString(&start[43U + cipher_hex_length], 32U))
  {
    return ESP_PACKET_INVALID;
  }

  *packet_length = full_length;
  return ESP_PACKET_READY;
}

static void ESP_HandleSecurePacket(const char *packet)
{
  SensorData_t parsed = {0};
  char plaintext[128];
  uint8_t session_id[ESP_SECURE_SESSION_ID_LEN];
  uint32_t frame_counter = 0U;
  uint32_t now = HAL_GetTick();
  bool flow_risk_started = false;
  bool frost_risk_started = false;
  bool mold_risk_started = false;

  if ((strcmp(packet, esp_receiver.last_hex) == 0) &&
      ((now - esp_receiver.last_hex_ms) < ESP_DUPLICATE_WINDOW_MS))
  {
    return;
  }

  snprintf(esp_receiver.last_hex, sizeof(esp_receiver.last_hex), "%s", packet);
  esp_receiver.last_hex_ms = now;

  if (memcmp(packet, ESP_SECURE_PACKET_PREFIX_V2, 4U) == 0)
  {
    if (!ESP_DecryptSecurePayloadV2(packet, plaintext, sizeof(plaintext), session_id, &frame_counter))
    {
      ESP_SetStatus("Guvenlik Hatasi", "Paket Reddedildi");
      return;
    }

    if (!ESP_AcceptReplayWindow(session_id, frame_counter))
    {
      ESP_SetStatus("Replay Engellendi", "Eski Paket");
      return;
    }
  }
  else if (!ESP_DecryptSecurePayloadV1(packet, plaintext, sizeof(plaintext)))
  {
    ESP_SetStatus("Guvenlik Hatasi", "Paket Reddedildi");
    return;
  }

  if (!ESP_ParseSensorPayload(plaintext, &parsed))
  {
    ESP_SetStatus("Paket Geldi", "Format Uyusmadi");
    return;
  }

  flow_risk_started = parsed.flow_risk && !sensor_data.flow_risk;
  frost_risk_started = parsed.frost_risk && !sensor_data.frost_risk;
  mold_risk_started = parsed.fan_active && !sensor_data.fan_active;

  snprintf(parsed.encrypted_hex, sizeof(parsed.encrypted_hex), "%s", packet);
  sensor_data = parsed;
  esp_receiver.last_packet_ms = now;

  if (frost_risk_started)
  {
    snprintf(alert_line1, sizeof(alert_line1), "Don Riski");
    snprintf(alert_line2, sizeof(alert_line2), "Role Aktif");
    alert_until_ms = now + ALERT_SHOW_MS;
  }
  else if (mold_risk_started)
  {
    snprintf(alert_line1, sizeof(alert_line1), "Nem Sic Artti");
    snprintf(alert_line2, sizeof(alert_line2), "Mantar Riski");
    alert_until_ms = now + ALERT_SHOW_MS;
  }
  else if (flow_risk_started)
  {
    snprintf(alert_line1, sizeof(alert_line1), "Boru Patlama");
    snprintf(alert_line2, sizeof(alert_line2), "Riski");
    alert_until_ms = now + ALERT_SHOW_MS;
  }

  ESP_SetStatus("Veri Cozuldu", "LCD Guncel");
}

static void ESP_ProcessTextBuffer(void)
{
  uint16_t i = 0U;
  uint16_t consume_until = 0U;
  uint16_t retain_from = esp_receiver.text_len;

  while (i < esp_receiver.text_len)
  {
    if ((i + 4U) <= esp_receiver.text_len &&
        ((memcmp(&esp_receiver.text_buffer[i], ESP_SECURE_PACKET_PREFIX, 4U) == 0) ||
         (memcmp(&esp_receiver.text_buffer[i], ESP_SECURE_PACKET_PREFIX_V2, 4U) == 0)))
    {
      size_t packet_length = 0U;
      EspPacketProbeResult_t probe =
          ESP_ProbeSecurePacket(&esp_receiver.text_buffer[i],
                                (size_t)(esp_receiver.text_len - i),
                                &packet_length);

      if (probe == ESP_PACKET_READY)
      {
        char packet[ESP_SECURE_PACKET_MAX_LEN];
        uint16_t packet_end = (uint16_t)(i + packet_length);

        while ((packet_end < esp_receiver.text_len) &&
               ((esp_receiver.text_buffer[packet_end] == '\r') ||
                (esp_receiver.text_buffer[packet_end] == '\n')))
        {
          packet_end++;
        }

        if (packet_length < sizeof(packet))
        {
          memcpy(packet, &esp_receiver.text_buffer[i], packet_length);
          packet[packet_length] = '\0';
          ESP_SetStatus("Paket Geldi", "Dogrulaniyor");
          ESP_HandleSecurePacket(packet);
        }

        consume_until = packet_end;
        i = packet_end;
        continue;
      }

      if (probe == ESP_PACKET_INCOMPLETE)
      {
        retain_from = i;
        break;
      }
    }

    i++;
    consume_until = i;
  }

  if (retain_from < esp_receiver.text_len)
  {
    if (retain_from > 0U)
    {
      ESP_ConsumeTextPrefix(retain_from);
    }
  }
  else if (consume_until > 0U)
  {
    ESP_ConsumeTextPrefix(consume_until);
  }
  else if (esp_receiver.text_len > (ESP_UART_NOISE_KEEP_LEN * 2U))
  {
    ESP_ConsumeTextPrefix((uint16_t)(esp_receiver.text_len - ESP_UART_NOISE_KEEP_LEN));
  }
}

static void ESP_ProcessStartupResponses(void)
{
  if (esp_receiver.server_ready || !esp_receiver.awaiting_response)
  {
    return;
  }

  if (ESP_ConsumeThroughToken("\r\nOK") ||
      ESP_ConsumeThroughToken("\nOK") ||
      ESP_ConsumeThroughToken("OK\r\n") ||
      ESP_ConsumeThroughToken("no change") ||
      ESP_ConsumeThroughToken("ALREADY CONNECTED"))
  {
    esp_receiver.awaiting_response = false;
    esp_receiver.last_action_ms = HAL_GetTick();
    esp_receiver.at_index++;
    return;
  }

  if (ESP_ConsumeThroughToken("busy p...") ||
      ESP_ConsumeThroughToken("busy s...") ||
      ESP_ConsumeThroughToken("busy"))
  {
    esp_receiver.awaiting_response = false;
    esp_receiver.last_action_ms = HAL_GetTick();
    ESP_SetStatus("ESP Mesgul", esp_init_commands[esp_receiver.at_index].line2);
    return;
  }

  if (ESP_ConsumeThroughToken("ERROR") ||
      ESP_ConsumeThroughToken("FAIL"))
  {
    esp_receiver.awaiting_response = false;
    esp_receiver.last_action_ms = HAL_GetTick();
    ESP_SetStatus("ESP Komut Hata", esp_init_commands[esp_receiver.at_index].line2);
  }
}

static void ESP_ServiceLinkHealth(void)
{
  uint32_t now = HAL_GetTick();
  uint32_t last_activity_ms = esp_receiver.last_packet_ms;

  if (!esp_receiver.server_ready)
  {
    return;
  }

  if (esp_receiver.last_rx_activity_ms > last_activity_ms)
  {
    last_activity_ms = esp_receiver.last_rx_activity_ms;
  }

  if (last_activity_ms == 0U)
  {
    last_activity_ms = esp_receiver.last_action_ms;
  }

  if ((now - last_activity_ms) >= ESP_PACKET_TIMEOUT_MS)
  {
    ESP_ForceReinit("ESP Yeniden", "Baglaniyor");
  }
}

static void ESP_StartUartReceive(void)
{
  if (!esp_receiver.uart_started)
  {
    esp_receiver.uart_started = true;
    HAL_UART_Receive_IT(&huart1, &esp_receiver.rx_byte, 1U);
  }
}

static void ESP_PollUart(void)
{
  bool received_any_byte = false;

  while (esp_receiver.rx_tail != esp_receiver.rx_head)
  {
    uint8_t byte = esp_receiver.rx_fifo[esp_receiver.rx_tail];
    esp_receiver.rx_tail = (uint16_t)((esp_receiver.rx_tail + 1U) % sizeof(esp_receiver.rx_fifo));
    received_any_byte = true;

    if (esp_receiver.text_len < (sizeof(esp_receiver.text_buffer) - 1U))
    {
      esp_receiver.text_buffer[esp_receiver.text_len++] = (char)byte;
      esp_receiver.text_buffer[esp_receiver.text_len] = '\0';
    }
    else
    {
      memmove(esp_receiver.text_buffer,
              &esp_receiver.text_buffer[esp_receiver.text_len - 256U],
              256U);
      esp_receiver.text_len = 256U;
      esp_receiver.text_buffer[esp_receiver.text_len++] = (char)byte;
      esp_receiver.text_buffer[esp_receiver.text_len] = '\0';
    }
  }

  if (received_any_byte && esp_receiver.server_ready && !sensor_data.valid)
  {
    esp_receiver.last_rx_activity_ms = HAL_GetTick();
    ESP_SetStatus("UART Veri", "Paket Bekleniyor");
  }
  else if (received_any_byte)
  {
    esp_receiver.last_rx_activity_ms = HAL_GetTick();
  }

  if (esp_receiver.text_len > 0U)
  {
    ESP_ProcessStartupResponses();

    if (esp_receiver.server_ready || !esp_receiver.awaiting_response)
    {
      ESP_ProcessTextBuffer();
    }
  }
}

static void ESP_ServiceStartup(void)
{
  uint32_t now = HAL_GetTick();

  if (!esp_receiver.init_started)
  {
    esp_receiver.init_started = true;
    esp_receiver.last_action_ms = now;
    ESP_SetStatus("ESP Basliyor", "Boot Bekleniyor");
    return;
  }

  if (esp_receiver.server_ready)
  {
    return;
  }

  if (esp_receiver.awaiting_response)
  {
    if ((now - esp_receiver.last_action_ms) >= esp_init_commands[esp_receiver.at_index].wait_ms)
    {
      esp_receiver.awaiting_response = false;
      esp_receiver.last_action_ms = now;
      ESP_SetStatus("ESP Timeout", esp_init_commands[esp_receiver.at_index].line2);
    }

    return;
  }

  if (esp_receiver.at_index >= (sizeof(esp_init_commands) / sizeof(esp_init_commands[0])))
  {
    esp_receiver.server_ready = true;
    ESP_SetStatus("ESP Sunucu Hazir", "Veri Bekleniyor");
    return;
  }

  if ((now - esp_receiver.last_action_ms) < esp_init_commands[esp_receiver.at_index].wait_ms)
  {
    return;
  }

  ESP_SendCommand(esp_init_commands[esp_receiver.at_index].command);
  ESP_SetStatus(esp_init_commands[esp_receiver.at_index].line1, esp_init_commands[esp_receiver.at_index].line2);
  esp_receiver.last_action_ms = now;
  esp_receiver.awaiting_response = true;
}
#endif

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_I2C1_Init();
  MX_USART1_UART_Init();
  MX_TIM1_Init();
  /* USER CODE BEGIN 2 */
  HAL_GPIO_WritePin(USER_LED_GPIO_Port, USER_LED_Pin, GPIO_PIN_SET);
  Buzzer_StopAlert();
#ifdef HAL_I2C_MODULE_ENABLED
  LCD_Init();
  LCD_Service();
#endif
#ifdef HAL_UART_MODULE_ENABLED
  ESP_StartUartReceive();
  ESP_SetStatus("ESP Basliyor", "Boot Bekleniyor");
#endif

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    static uint32_t last_led_toggle_ms = 0U;

    if ((HAL_GetTick() - last_led_toggle_ms) >= 500U)
    {
      last_led_toggle_ms = HAL_GetTick();
      HAL_GPIO_TogglePin(USER_LED_GPIO_Port, USER_LED_Pin);
    }

#ifdef HAL_UART_MODULE_ENABLED
    ESP_ServiceStartup();
    ESP_PollUart();
    ESP_ServiceLinkHealth();
#endif

    Buzzer_Service();

#ifdef HAL_I2C_MODULE_ENABLED
    LCD_Service();
#endif

    HAL_Delay(1);
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 64;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV4;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief I2C1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C1_Init(void)
{

  /* USER CODE BEGIN I2C1_Init 0 */

  /* USER CODE END I2C1_Init 0 */

  /* USER CODE BEGIN I2C1_Init 1 */

  /* USER CODE END I2C1_Init 1 */
  hi2c1.Instance = I2C1;
  hi2c1.Init.ClockSpeed = 100000;
  hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C1_Init 2 */

  /* USER CODE END I2C1_Init 2 */

}

/**
  * @brief TIM1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM1_Init(void)
{

  /* USER CODE BEGIN TIM1_Init 0 */

  /* USER CODE END TIM1_Init 0 */

  TIM_MasterConfigTypeDef sMasterConfig = {0};
  TIM_OC_InitTypeDef sConfigOC = {0};
  TIM_BreakDeadTimeConfigTypeDef sBreakDeadTimeConfig = {0};

  /* USER CODE BEGIN TIM1_Init 1 */

  /* USER CODE END TIM1_Init 1 */
  htim1.Instance = TIM1;
  htim1.Init.Prescaler = 63;
  htim1.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim1.Init.Period = 499;
  htim1.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim1.Init.RepetitionCounter = 0;
  htim1.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_PWM_Init(&htim1) != HAL_OK)
  {
    Error_Handler();
  }
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_RESET;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
  if (HAL_TIMEx_MasterConfigSynchronization(&htim1, &sMasterConfig) != HAL_OK)
  {
    Error_Handler();
  }
  sConfigOC.OCMode = TIM_OCMODE_PWM1;
  sConfigOC.Pulse = 0;
  sConfigOC.OCPolarity = TIM_OCPOLARITY_HIGH;
  sConfigOC.OCNPolarity = TIM_OCNPOLARITY_HIGH;
  sConfigOC.OCFastMode = TIM_OCFAST_DISABLE;
  sConfigOC.OCIdleState = TIM_OCIDLESTATE_RESET;
  sConfigOC.OCNIdleState = TIM_OCNIDLESTATE_RESET;
  if (HAL_TIM_PWM_ConfigChannel(&htim1, &sConfigOC, TIM_CHANNEL_1) != HAL_OK)
  {
    Error_Handler();
  }
  sBreakDeadTimeConfig.OffStateRunMode = TIM_OSSR_DISABLE;
  sBreakDeadTimeConfig.OffStateIDLEMode = TIM_OSSI_DISABLE;
  sBreakDeadTimeConfig.LockLevel = TIM_LOCKLEVEL_OFF;
  sBreakDeadTimeConfig.DeadTime = 0;
  sBreakDeadTimeConfig.BreakState = TIM_BREAK_DISABLE;
  sBreakDeadTimeConfig.BreakPolarity = TIM_BREAKPOLARITY_HIGH;
  sBreakDeadTimeConfig.AutomaticOutput = TIM_AUTOMATICOUTPUT_DISABLE;
  if (HAL_TIMEx_ConfigBreakDeadTime(&htim1, &sBreakDeadTimeConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN TIM1_Init 2 */

  /* USER CODE END TIM1_Init 2 */
  HAL_TIM_MspPostInit(&htim1);

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */
  HAL_GPIO_WritePin(USER_LED_GPIO_Port, USER_LED_Pin, GPIO_PIN_SET);

  GPIO_InitStruct.Pin = USER_LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(USER_LED_GPIO_Port, &GPIO_InitStruct);

#ifndef HAL_TIM_MODULE_ENABLED
  HAL_GPIO_WritePin(BUZZER_GPIO_Port, BUZZER_Pin, GPIO_PIN_RESET);

  GPIO_InitStruct.Pin = BUZZER_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(BUZZER_GPIO_Port, &GPIO_InitStruct);
#endif

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
#ifdef HAL_UART_MODULE_ENABLED
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
  if (huart->Instance == USART1)
  {
    uint16_t next_head = (uint16_t)((esp_receiver.rx_head + 1U) % sizeof(esp_receiver.rx_fifo));

    if (next_head != esp_receiver.rx_tail)
    {
      esp_receiver.rx_fifo[esp_receiver.rx_head] = esp_receiver.rx_byte;
      esp_receiver.rx_head = next_head;
    }

    HAL_UART_Receive_IT(&huart1, &esp_receiver.rx_byte, 1U);
  }
}

void HAL_UART_ErrorCallback(UART_HandleTypeDef *huart)
{
  if (huart->Instance == USART1)
  {
    __HAL_UART_CLEAR_OREFLAG(&huart1);
    HAL_UART_Receive_IT(&huart1, &esp_receiver.rx_byte, 1U);
  }
}
#endif

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
