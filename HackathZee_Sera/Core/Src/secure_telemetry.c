#include "secure_telemetry.h"

#include "main.h"
#include "secure_link_config.h"

#include <string.h>

#define AES128_BLOCK_SIZE 16U
#define SHA256_BLOCK_SIZE 64U
#define SHA256_DIGEST_SIZE 32U

typedef struct
{
  uint8_t round_keys[176];
} aes128_ctx_t;

typedef struct
{
  uint32_t state[8];
  uint64_t bit_length;
  uint8_t data[64];
  uint32_t data_len;
} sha256_ctx_t;

static uint32_t s_secure_frame_counter = 0U;
static uint8_t s_cached_keys_valid = 0U;
static uint8_t s_session_id_valid = 0U;
static char s_cached_master_secret[96] = {0};
static aes128_ctx_t s_cached_aes_ctx;
static uint8_t s_cached_hmac_key[32];
static uint8_t s_session_id[SECURE_TELEMETRY_SESSION_ID_SIZE];

static const uint8_t s_aes_sbox[256] = {
    0x63U, 0x7CU, 0x77U, 0x7BU, 0xF2U, 0x6BU, 0x6FU, 0xC5U, 0x30U, 0x01U, 0x67U, 0x2BU, 0xFEU, 0xD7U, 0xABU, 0x76U,
    0xCAU, 0x82U, 0xC9U, 0x7DU, 0xFAU, 0x59U, 0x47U, 0xF0U, 0xADU, 0xD4U, 0xA2U, 0xAFU, 0x9CU, 0xA4U, 0x72U, 0xC0U,
    0xB7U, 0xFDU, 0x93U, 0x26U, 0x36U, 0x3FU, 0xF7U, 0xCCU, 0x34U, 0xA5U, 0xE5U, 0xF1U, 0x71U, 0xD8U, 0x31U, 0x15U,
    0x04U, 0xC7U, 0x23U, 0xC3U, 0x18U, 0x96U, 0x05U, 0x9AU, 0x07U, 0x12U, 0x80U, 0xE2U, 0xEBU, 0x27U, 0xB2U, 0x75U,
    0x09U, 0x83U, 0x2CU, 0x1AU, 0x1BU, 0x6EU, 0x5AU, 0xA0U, 0x52U, 0x3BU, 0xD6U, 0xB3U, 0x29U, 0xE3U, 0x2FU, 0x84U,
    0x53U, 0xD1U, 0x00U, 0xEDU, 0x20U, 0xFCU, 0xB1U, 0x5BU, 0x6AU, 0xCBU, 0xBEU, 0x39U, 0x4AU, 0x4CU, 0x58U, 0xCFU,
    0xD0U, 0xEFU, 0xAAU, 0xFBU, 0x43U, 0x4DU, 0x33U, 0x85U, 0x45U, 0xF9U, 0x02U, 0x7FU, 0x50U, 0x3CU, 0x9FU, 0xA8U,
    0x51U, 0xA3U, 0x40U, 0x8FU, 0x92U, 0x9DU, 0x38U, 0xF5U, 0xBCU, 0xB6U, 0xDAU, 0x21U, 0x10U, 0xFFU, 0xF3U, 0xD2U,
    0xCDU, 0x0CU, 0x13U, 0xECU, 0x5FU, 0x97U, 0x44U, 0x17U, 0xC4U, 0xA7U, 0x7EU, 0x3DU, 0x64U, 0x5DU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4FU, 0xDCU, 0x22U, 0x2AU, 0x90U, 0x88U, 0x46U, 0xEEU, 0xB8U, 0x14U, 0xDEU, 0x5EU, 0x0BU, 0xDBU,
    0xE0U, 0x32U, 0x3AU, 0x0AU, 0x49U, 0x06U, 0x24U, 0x5CU, 0xC2U, 0xD3U, 0xACU, 0x62U, 0x91U, 0x95U, 0xE4U, 0x79U,
    0xE7U, 0xC8U, 0x37U, 0x6DU, 0x8DU, 0xD5U, 0x4EU, 0xA9U, 0x6CU, 0x56U, 0xF4U, 0xEAU, 0x65U, 0x7AU, 0xAEU, 0x08U,
    0xBAU, 0x78U, 0x25U, 0x2EU, 0x1CU, 0xA6U, 0xB4U, 0xC6U, 0xE8U, 0xDDU, 0x74U, 0x1FU, 0x4BU, 0xBDU, 0x8BU, 0x8AU,
    0x70U, 0x3EU, 0xB5U, 0x66U, 0x48U, 0x03U, 0xF6U, 0x0EU, 0x61U, 0x35U, 0x57U, 0xB9U, 0x86U, 0xC1U, 0x1DU, 0x9EU,
    0xE1U, 0xF8U, 0x98U, 0x11U, 0x69U, 0xD9U, 0x8EU, 0x94U, 0x9BU, 0x1EU, 0x87U, 0xE9U, 0xCEU, 0x55U, 0x28U, 0xDFU,
    0x8CU, 0xA1U, 0x89U, 0x0DU, 0xBFU, 0xE6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2DU, 0x0FU, 0xB0U, 0x54U, 0xBBU, 0x16U};

static const uint8_t s_aes_rcon[11] = {
    0x00U, 0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U, 0x1BU, 0x36U};

static const uint32_t s_sha256_k[64] = {
    0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL, 0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
    0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL, 0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
    0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL, 0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
    0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL, 0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
    0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL, 0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
    0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL, 0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
    0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL, 0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
    0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL, 0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL};

static uint32_t sha256_rotr(uint32_t value, uint32_t bits)
{
  return (value >> bits) | (value << (32U - bits));
}

static uint8_t aes_xtime(uint8_t value)
{
  return (uint8_t)((value << 1) ^ (((value >> 7) & 0x01U) * 0x1BU));
}

static void bytes_to_hex(const uint8_t *input, size_t input_len, char *output)
{
  static const char hex_digits[] = "0123456789ABCDEF";

  for (size_t i = 0U; i < input_len; i++)
  {
    output[i * 2U] = hex_digits[(input[i] >> 4) & 0x0FU];
    output[(i * 2U) + 1U] = hex_digits[input[i] & 0x0FU];
  }
}

static void store_be32(uint32_t value, uint8_t output[4])
{
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

static void secure_increment_counter(uint8_t counter[AES128_BLOCK_SIZE])
{
  for (int32_t i = (int32_t)AES128_BLOCK_SIZE - 1; i >= 0; i--)
  {
    counter[i]++;
    if (counter[i] != 0U)
    {
      break;
    }
  }
}

static void aes_key_expansion(aes128_ctx_t *ctx, const uint8_t key[16])
{
  uint32_t bytes_generated = 16U;
  uint32_t rcon_index = 1U;
  uint8_t temp[4];

  memcpy(ctx->round_keys, key, 16U);

  while (bytes_generated < sizeof(ctx->round_keys))
  {
    for (uint32_t i = 0U; i < 4U; i++)
    {
      temp[i] = ctx->round_keys[bytes_generated - 4U + i];
    }

    if ((bytes_generated % 16U) == 0U)
    {
      uint8_t swap = temp[0];
      temp[0] = s_aes_sbox[temp[1]];
      temp[1] = s_aes_sbox[temp[2]];
      temp[2] = s_aes_sbox[temp[3]];
      temp[3] = s_aes_sbox[swap];
      temp[0] ^= s_aes_rcon[rcon_index++];
    }

    for (uint32_t i = 0U; i < 4U; i++)
    {
      ctx->round_keys[bytes_generated] = ctx->round_keys[bytes_generated - 16U] ^ temp[i];
      bytes_generated++;
    }
  }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *round_key)
{
  for (uint32_t i = 0U; i < 16U; i++)
  {
    state[i] ^= round_key[i];
  }
}

static void aes_sub_bytes(uint8_t state[16])
{
  for (uint32_t i = 0U; i < 16U; i++)
  {
    state[i] = s_aes_sbox[state[i]];
  }
}

static void aes_shift_rows(uint8_t state[16])
{
  uint8_t temp = 0U;

  temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  temp = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = temp;
}

static void aes_mix_columns(uint8_t state[16])
{
  for (uint32_t i = 0U; i < 16U; i += 4U)
  {
    uint8_t a0 = state[i];
    uint8_t a1 = state[i + 1U];
    uint8_t a2 = state[i + 2U];
    uint8_t a3 = state[i + 3U];
    uint8_t mix = a0 ^ a1 ^ a2 ^ a3;

    state[i] ^= mix ^ aes_xtime((uint8_t)(a0 ^ a1));
    state[i + 1U] ^= mix ^ aes_xtime((uint8_t)(a1 ^ a2));
    state[i + 2U] ^= mix ^ aes_xtime((uint8_t)(a2 ^ a3));
    state[i + 3U] ^= mix ^ aes_xtime((uint8_t)(a3 ^ a0));
  }
}

static void aes_encrypt_block(const aes128_ctx_t *ctx, const uint8_t input[16], uint8_t output[16])
{
  uint8_t state[16];

  memcpy(state, input, sizeof(state));
  aes_add_round_key(state, ctx->round_keys);

  for (uint32_t round = 1U; round < 10U; round++)
  {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, &ctx->round_keys[round * 16U]);
  }

  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_add_round_key(state, &ctx->round_keys[160U]);
  memcpy(output, state, sizeof(state));
}

static void aes_ctr_crypt(
    const aes128_ctx_t *ctx,
    const uint8_t iv[16],
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
  uint8_t counter[16];
  uint8_t stream_block[16];
  size_t offset = 0U;

  memcpy(counter, iv, sizeof(counter));

  while (offset < length)
  {
    aes_encrypt_block(ctx, counter, stream_block);

    for (size_t i = 0U; (i < AES128_BLOCK_SIZE) && (offset < length); i++, offset++)
    {
      output[offset] = input[offset] ^ stream_block[i];
    }

    secure_increment_counter(counter);
  }
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
  uint32_t w[64];
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];

  for (uint32_t i = 0U; i < 16U; i++)
  {
    w[i] = ((uint32_t)data[i * 4U] << 24U) |
           ((uint32_t)data[(i * 4U) + 1U] << 16U) |
           ((uint32_t)data[(i * 4U) + 2U] << 8U) |
           (uint32_t)data[(i * 4U) + 3U];
  }

  for (uint32_t i = 16U; i < 64U; i++)
  {
    uint32_t s0 = sha256_rotr(w[i - 15U], 7U) ^ sha256_rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
    uint32_t s1 = sha256_rotr(w[i - 2U], 17U) ^ sha256_rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
    w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
  }

  for (uint32_t i = 0U; i < 64U; i++)
  {
    uint32_t s1 = sha256_rotr(e, 6U) ^ sha256_rotr(e, 11U) ^ sha256_rotr(e, 25U);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + s1 + ch + s_sha256_k[i] + w[i];
    uint32_t s0 = sha256_rotr(a, 2U) ^ sha256_rotr(a, 13U) ^ sha256_rotr(a, 22U);
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

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
  ctx->data_len = 0U;
  ctx->bit_length = 0U;
  ctx->state[0] = 0x6A09E667UL;
  ctx->state[1] = 0xBB67AE85UL;
  ctx->state[2] = 0x3C6EF372UL;
  ctx->state[3] = 0xA54FF53AUL;
  ctx->state[4] = 0x510E527FUL;
  ctx->state[5] = 0x9B05688CUL;
  ctx->state[6] = 0x1F83D9ABUL;
  ctx->state[7] = 0x5BE0CD19UL;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
  for (size_t i = 0U; i < len; i++)
  {
    ctx->data[ctx->data_len++] = data[i];
    if (ctx->data_len == 64U)
    {
      sha256_transform(ctx, ctx->data);
      ctx->bit_length += 512U;
      ctx->data_len = 0U;
    }
  }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32])
{
  uint32_t i = ctx->data_len;

  ctx->data[i++] = 0x80U;

  if (i > 56U)
  {
    while (i < 64U)
    {
      ctx->data[i++] = 0x00U;
    }

    sha256_transform(ctx, ctx->data);
    i = 0U;
  }

  while (i < 56U)
  {
    ctx->data[i++] = 0x00U;
  }

  ctx->bit_length += (uint64_t)ctx->data_len * 8ULL;
  ctx->data[63] = (uint8_t)(ctx->bit_length);
  ctx->data[62] = (uint8_t)(ctx->bit_length >> 8);
  ctx->data[61] = (uint8_t)(ctx->bit_length >> 16);
  ctx->data[60] = (uint8_t)(ctx->bit_length >> 24);
  ctx->data[59] = (uint8_t)(ctx->bit_length >> 32);
  ctx->data[58] = (uint8_t)(ctx->bit_length >> 40);
  ctx->data[57] = (uint8_t)(ctx->bit_length >> 48);
  ctx->data[56] = (uint8_t)(ctx->bit_length >> 56);
  sha256_transform(ctx, ctx->data);

  for (i = 0U; i < 4U; i++)
  {
    hash[i] = (uint8_t)(ctx->state[0] >> (24U - (i * 8U)));
    hash[i + 4U] = (uint8_t)(ctx->state[1] >> (24U - (i * 8U)));
    hash[i + 8U] = (uint8_t)(ctx->state[2] >> (24U - (i * 8U)));
    hash[i + 12U] = (uint8_t)(ctx->state[3] >> (24U - (i * 8U)));
    hash[i + 16U] = (uint8_t)(ctx->state[4] >> (24U - (i * 8U)));
    hash[i + 20U] = (uint8_t)(ctx->state[5] >> (24U - (i * 8U)));
    hash[i + 24U] = (uint8_t)(ctx->state[6] >> (24U - (i * 8U)));
    hash[i + 28U] = (uint8_t)(ctx->state[7] >> (24U - (i * 8U)));
  }
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[32])
{
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

static void hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *part1,
    size_t part1_len,
    const uint8_t *part2,
    size_t part2_len,
    uint8_t digest[32])
{
  uint8_t key_block[SHA256_BLOCK_SIZE];
  uint8_t inner_digest[SHA256_DIGEST_SIZE];
  uint8_t ipad[SHA256_BLOCK_SIZE];
  uint8_t opad[SHA256_BLOCK_SIZE];
  uint8_t hashed_key[SHA256_DIGEST_SIZE];
  sha256_ctx_t ctx;

  memset(key_block, 0, sizeof(key_block));

  if (key_len > SHA256_BLOCK_SIZE)
  {
    sha256_hash(key, key_len, hashed_key);
    memcpy(key_block, hashed_key, sizeof(hashed_key));
  }
  else
  {
    memcpy(key_block, key, key_len);
  }

  for (size_t i = 0U; i < SHA256_BLOCK_SIZE; i++)
  {
    ipad[i] = key_block[i] ^ 0x36U;
    opad[i] = key_block[i] ^ 0x5CU;
  }

  sha256_init(&ctx);
  sha256_update(&ctx, ipad, sizeof(ipad));
  sha256_update(&ctx, part1, part1_len);
  sha256_update(&ctx, part2, part2_len);
  sha256_final(&ctx, inner_digest);

  sha256_init(&ctx);
  sha256_update(&ctx, opad, sizeof(opad));
  sha256_update(&ctx, inner_digest, sizeof(inner_digest));
  sha256_final(&ctx, digest);
}

static void build_link_context_digest(
    const char *sender_device_id,
    const char *receiver_device_id,
    uint8_t digest[32])
{
  static const uint8_t context_label[] = "SECURE-LINK-CONTEXT";
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, context_label, sizeof(context_label) - 1U);
  sha256_update(&ctx, (const uint8_t *)sender_device_id, strlen(sender_device_id));
  sha256_update(&ctx, (const uint8_t *)receiver_device_id, strlen(receiver_device_id));
  sha256_final(&ctx, digest);
}

static void derive_keys(
    const char *master_secret,
    const char *sender_device_id,
    const char *receiver_device_id,
    uint8_t aes_key[16],
    uint8_t hmac_key[32])
{
  static const uint8_t aes_label[] = "AES-128-CTR";
  static const uint8_t hmac_label[] = "HMAC-SHA256";
  uint8_t link_context_digest[32];
  uint8_t digest[32];
  sha256_ctx_t ctx;
  size_t secret_len = strlen(master_secret);

  build_link_context_digest(sender_device_id, receiver_device_id, link_context_digest);

  sha256_init(&ctx);
  sha256_update(&ctx, aes_label, sizeof(aes_label) - 1U);
  sha256_update(&ctx, link_context_digest, sizeof(link_context_digest));
  sha256_update(&ctx, (const uint8_t *)master_secret, secret_len);
  sha256_final(&ctx, digest);
  memcpy(aes_key, digest, 16U);

  sha256_init(&ctx);
  sha256_update(&ctx, hmac_label, sizeof(hmac_label) - 1U);
  sha256_update(&ctx, link_context_digest, sizeof(link_context_digest));
  sha256_update(&ctx, (const uint8_t *)master_secret, secret_len);
  sha256_final(&ctx, hmac_key);
}

static uint8_t load_cached_key_material(
    const char *master_secret,
    const char *sender_device_id,
    const char *receiver_device_id)
{
  uint8_t aes_key[16];
  size_t secret_len = strlen(master_secret);

  if ((s_cached_keys_valid != 0U) &&
      (strncmp(s_cached_master_secret, master_secret, sizeof(s_cached_master_secret)) == 0))
  {
    return 1U;
  }

  if (secret_len >= sizeof(s_cached_master_secret))
  {
    return 0U;
  }

  derive_keys(master_secret, sender_device_id, receiver_device_id, aes_key, s_cached_hmac_key);
  aes_key_expansion(&s_cached_aes_ctx, aes_key);
  memcpy(s_cached_master_secret, master_secret, secret_len + 1U);
  s_cached_keys_valid = 1U;
  s_session_id_valid = 0U;
  return 1U;
}

static void ensure_session_id(
    const char *master_secret,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t session_id[SECURE_TELEMETRY_SESSION_ID_SIZE])
{
  static const uint8_t session_label[] = "SECURE-SESSION";
  const uint8_t *uid = (const uint8_t *)UID_BASE;
  uint8_t digest[32];
  uint8_t scratch[4];
  sha256_ctx_t ctx;

  if (s_session_id_valid != 0U)
  {
    memcpy(session_id, s_session_id, SECURE_TELEMETRY_SESSION_ID_SIZE);
    return;
  }

  sha256_init(&ctx);
  sha256_update(&ctx, session_label, sizeof(session_label) - 1U);
  sha256_update(&ctx, (const uint8_t *)master_secret, strlen(master_secret));
  sha256_update(&ctx, (const uint8_t *)SECURE_LINK_SENDER_DEVICE_ID, strlen(SECURE_LINK_SENDER_DEVICE_ID));
  sha256_update(&ctx, (const uint8_t *)SECURE_LINK_RECEIVER_DEVICE_ID, strlen(SECURE_LINK_RECEIVER_DEVICE_ID));
  sha256_update(&ctx, uid, 12U);

  store_be32(HAL_GetTick(), scratch);
  sha256_update(&ctx, scratch, sizeof(scratch));

  store_be32(DWT->CYCCNT, scratch);
  sha256_update(&ctx, scratch, sizeof(scratch));

  sha256_update(&ctx, plaintext, plaintext_len);
  sha256_final(&ctx, digest);

  memcpy(s_session_id, digest, SECURE_TELEMETRY_SESSION_ID_SIZE);
  memcpy(session_id, s_session_id, SECURE_TELEMETRY_SESSION_ID_SIZE);
  s_session_id_valid = 1U;
}

static void build_iv(
    const char *master_secret,
    const uint8_t session_id[SECURE_TELEMETRY_SESSION_ID_SIZE],
    uint32_t frame_counter,
    uint8_t iv[16])
{
  static const uint8_t iv_label[] = "SECURE-IV";
  const uint8_t *uid = (const uint8_t *)UID_BASE;
  uint8_t digest[32];
  uint8_t scratch[4];
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, iv_label, sizeof(iv_label) - 1U);
  sha256_update(&ctx, (const uint8_t *)master_secret, strlen(master_secret));
  sha256_update(&ctx, (const uint8_t *)SECURE_LINK_SENDER_DEVICE_ID, strlen(SECURE_LINK_SENDER_DEVICE_ID));
  sha256_update(&ctx, (const uint8_t *)SECURE_LINK_RECEIVER_DEVICE_ID, strlen(SECURE_LINK_RECEIVER_DEVICE_ID));
  sha256_update(&ctx, session_id, SECURE_TELEMETRY_SESSION_ID_SIZE);
  sha256_update(&ctx, uid, 12U);
  store_be32(frame_counter, scratch);
  sha256_update(&ctx, scratch, sizeof(scratch));
  sha256_final(&ctx, digest);

  memcpy(iv, digest, 16U);
}

uint8_t SecureTelemetry_Encode(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *master_secret,
    char *ascii_packet,
    size_t ascii_packet_len)
{
  uint8_t session_id[SECURE_TELEMETRY_SESSION_ID_SIZE];
  uint8_t frame_counter_bytes[SECURE_TELEMETRY_FRAME_COUNTER_SIZE];
  uint8_t iv[SECURE_TELEMETRY_IV_SIZE];
  uint8_t ciphertext[SECURE_TELEMETRY_MAX_PLAINTEXT_LEN];
  uint8_t auth_buffer[
      SECURE_TELEMETRY_SESSION_ID_SIZE +
      SECURE_TELEMETRY_FRAME_COUNTER_SIZE +
      SECURE_TELEMETRY_IV_SIZE +
      SECURE_TELEMETRY_MAX_PLAINTEXT_LEN];
  uint8_t tag[SHA256_DIGEST_SIZE];
  uint32_t frame_counter = 0U;
  size_t required_len = 0U;
  char *cursor = ascii_packet;

  if ((plaintext == NULL) || (master_secret == NULL) || (ascii_packet == NULL))
  {
    return 0U;
  }

  if ((plaintext_len == 0U) || (plaintext_len > SECURE_TELEMETRY_MAX_PLAINTEXT_LEN))
  {
    return 0U;
  }

  required_len = 104U + (plaintext_len * 2U);
  if (ascii_packet_len < required_len)
  {
    return 0U;
  }

  if (load_cached_key_material(
          master_secret,
          SECURE_LINK_SENDER_DEVICE_ID,
          SECURE_LINK_RECEIVER_DEVICE_ID) == 0U)
  {
    return 0U;
  }

  ensure_session_id(master_secret, plaintext, plaintext_len, session_id);

  s_secure_frame_counter++;
  frame_counter = s_secure_frame_counter;
  store_be32(frame_counter, frame_counter_bytes);

  build_iv(master_secret, session_id, frame_counter, iv);
  aes_ctr_crypt(&s_cached_aes_ctx, iv, plaintext, ciphertext, plaintext_len);

  memcpy(auth_buffer, session_id, sizeof(session_id));
  memcpy(&auth_buffer[sizeof(session_id)], frame_counter_bytes, sizeof(frame_counter_bytes));
  memcpy(&auth_buffer[sizeof(session_id) + sizeof(frame_counter_bytes)], iv, sizeof(iv));
  memcpy(&auth_buffer[sizeof(session_id) + sizeof(frame_counter_bytes) + sizeof(iv)], ciphertext, plaintext_len);
  hmac_sha256(
      s_cached_hmac_key,
      sizeof(s_cached_hmac_key),
      auth_buffer,
      sizeof(session_id) + sizeof(frame_counter_bytes),
      &auth_buffer[sizeof(session_id) + sizeof(frame_counter_bytes)],
      sizeof(iv) + plaintext_len,
      tag);

  memcpy(cursor, "ST2:", 4U);
  cursor += 4U;

  cursor[0] = "0123456789ABCDEF"[(plaintext_len >> 12) & 0x0FU];
  cursor[1] = "0123456789ABCDEF"[(plaintext_len >> 8) & 0x0FU];
  cursor[2] = "0123456789ABCDEF"[(plaintext_len >> 4) & 0x0FU];
  cursor[3] = "0123456789ABCDEF"[plaintext_len & 0x0FU];
  cursor += 4U;

  *cursor++ = ':';
  bytes_to_hex(session_id, sizeof(session_id), cursor);
  cursor += (sizeof(session_id) * 2U);

  *cursor++ = ':';
  bytes_to_hex(frame_counter_bytes, sizeof(frame_counter_bytes), cursor);
  cursor += (sizeof(frame_counter_bytes) * 2U);

  *cursor++ = ':';
  bytes_to_hex(iv, sizeof(iv), cursor);
  cursor += (sizeof(iv) * 2U);

  *cursor++ = ':';
  bytes_to_hex(ciphertext, plaintext_len, cursor);
  cursor += (plaintext_len * 2U);

  *cursor++ = ':';
  bytes_to_hex(tag, SECURE_TELEMETRY_TAG_SIZE, cursor);
  cursor += (SECURE_TELEMETRY_TAG_SIZE * 2U);

  *cursor++ = '\r';
  *cursor++ = '\n';
  *cursor = '\0';
  return 1U;
}
