/**
 * Response handling.
 *
 * @author Matthias L. Jugel, Niranjan Rao
 * @date 2017-12-07
 *
 * Copyright 2016, 2017 ubirch GmbH (https://ubirch.com)
 *
 * == LICENSE ==
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mbed.h>
#include <jsmn/jsmn.h>
#include <ubirch-mbed-debug/source/edebug.h>
#include <mbed-os/features/mbedtls/inc/mbedtls/base64.h>
#include <ubirch-mbed-nacl-cm0/source/nacl/armnacl.h>

#define MAX_INTERVAL        1800000
#define PROTOCOL_VERSION_MIN "0.0"
#define P_SIGNATURE        "s"
#define P_VERSION          "v"
#define P_KEY              "k"
#define P_PAYLOAD          "p"
#define P_SEND_INTERVAL    "i"
#define P_DEVICE_ID        "id"
#define P_TIMESTAMP        "ts"

#define E_OK                     0b00000000
#define E_SENSOR_FAILED          0b00000001 //1
#define E_PROTOCOL_FAIL          0b00000010 //2
#define E_SIG_VRFY_FAIL          0b00000100 //4
#define E_JSON_FAILED            0b00001000 //8
#define E_WDOG_RESET             0b00010000
#define E_PROVISION_FAILED       0b00100000
#define E_CONFIG_UPDATE_FAILED   0b01000000
#define E_RECEIVE_DATA_FAILED    0b10000000


extern int errors;
extern int interval;

//! @brief JSMN helper function to print the current token for debugging
static void print_token(const char *prefix, const char *response, jsmntok_t *token) {
    const size_t token_size = (const size_t) (token->end - token->start);
    EDEBUG_PRINTF("%s ", prefix);
    for (unsigned int i = 0; i < token_size; i++) EDEBUG_PRINTF("%c", *(response + token->start + i));
    EDEBUG_PRINTF("\r\n");
}


//! @brief JSMN helper function to compare token values
static int jsoneq(const char *json, jsmntok_t *token, const char *key) {
  if (token->type == JSMN_STRING &&
      strlen(key) == (size_t)(token->end - token->start) &&
      strncmp(json + token->start, key, (size_t)(token->end - token->start)) == 0) {
    return 0;
  }
  return -1;
}

/*!
 * Process the JSON response from the backend. It should contain configuration
 * parameters that need to be set. The response must be signed and will be
 * checked for signature match and protocol version.
 *
 * @param response the request response, will be freed here
 * @param key where the key from the response will be stored
 * @param signature the extracted payload signature
 * @return the payload string
 */
char * process_response(char *response, size_t responseLen,
                        unsigned char key[crypto_sign_PUBLICKEYBYTES],
                        unsigned char signature[crypto_sign_BYTES]) {
    char *payload = NULL;

    jsmntok_t *token;
    jsmn_parser parser = {};
    jsmn_init(&parser);

    // identify the number of tokens in our response, we expect 13
    const int token_count = jsmn_parse(&parser, response, responseLen, NULL, 0);
    // TODO check token count and return if too many
    token = (jsmntok_t *) malloc(sizeof(*token) * token_count);

    // reset parser, parse and store tokens
    jsmn_init(&parser);
    const int parsed_token_count = jsmn_parse(&parser, response, responseLen, token, (unsigned int) token_count);
    if (parsed_token_count == token_count && token[0].type == JSMN_OBJECT) {
        int index = 0;
        while (++index < token_count) {
            if (jsoneq(response, &token[index], P_DEVICE_ID) == 0 && token[index + 1].type == JSMN_STRING) {
                index++;
                print_token("D_ID", response, &token[index]);
            } else if (jsoneq(response, &token[index], P_VERSION) == 0 && token[index + 1].type == JSMN_STRING) {
                index++;
                if (strncmp(response + token[index].start, PROTOCOL_VERSION_MIN, 3) != 0) {
                    print_token("protocol version mismatch:", response, &token[index]);

                    // do not continue if the version does not match, free already copied payload or sig
                    errors |= E_PROTOCOL_FAIL;
                    break;
                }
            } else if (jsoneq(response, &token[index], P_KEY) == 0 && token[index + 1].type == JSMN_STRING) {
                index++;
                print_token("key:", response, &token[index]);

                size_t key_length;
                mbedtls_base64_decode(key, crypto_sign_PUBLICKEYBYTES, &key_length,
                                      reinterpret_cast<const unsigned char *>(response + token[index].start),
                                      (size_t) (token[index].end - token[index].start));

                if (!key_length) {
                    EDEBUG_PRINTF("ERROR: decoding key\r\n");
                }
            } else if (jsoneq(response, &token[index], P_SIGNATURE) == 0 && token[index + 1].type == JSMN_STRING) {
                index++;
                print_token("signature:", response, &token[index]);

                size_t hash_length; // = crypto_sign_BYTES;
                mbedtls_base64_decode(signature, crypto_sign_BYTES, &hash_length,
                                      reinterpret_cast<const unsigned char *>(response + token[index].start),
                                      (size_t) (token[index].end - token[index].start));

                if (!hash_length) {
                    EDEBUG_PRINTF("ERROR: decoding hash digest\r\n");
                }
            } else if (jsoneq(response, &token[index], P_PAYLOAD) == 0 && token[index + 1].type == JSMN_OBJECT) {
                index++;
                print_token("payload:", response, &token[index]);

                // extract payload from json
                size_t payload_length = (uint8_t) (token[index].end - token[index].start);
                payload = strndup(response + token[index].start, payload_length);
                payload[payload_length] = '\0';

                index += 2 * token[index].size;
            } else if (jsoneq(response, &token[index], P_TIMESTAMP) == 0 && token[index + 1].type == JSMN_STRING) {
                index++;
                print_token("TimeStamp:", response, &token[index]);
            } else {
                // simply ignore unknown keys
                print_token("unknown key:", response, &token[index]);
                index++;
            }
        }
    } else {
        EDEBUG_PRINTF("No JSON Object\r\n");
        errors |= E_JSON_FAILED;
    }

    // free used heap (token)
    free(token);

    return payload;
}

// convert a number of characters into an unsigned integer value
unsigned int to_uint(const char *ptr, size_t len) {
    unsigned int ret = 0;
    for (uint8_t i = 0; i < len; i++) {
        ret = (ret * 10) + (ptr[i] - '0');
    }
    return ret;
}

void process_payload(char *payload) {
    jsmntok_t *token;
    jsmn_parser parser = {};
    jsmn_init(&parser);

    // identify the number of tokens in our response, we expect 13
    const uint8_t token_count = (const uint8_t) jsmn_parse(&parser, payload, strlen(payload), NULL, 0);
    token = (jsmntok_t *) malloc(sizeof(*token) * token_count);

    // reset parser, parse and store tokens
    jsmn_init(&parser);
    if (jsmn_parse(&parser, payload, strlen(payload), token, token_count) == token_count &&
        token[0].type == JSMN_OBJECT) {
        uint8_t index = 0;
        while (++index < token_count) {
            if (jsoneq(payload, &token[index], P_SEND_INTERVAL) == 0 && token[index + 1].type == JSMN_PRIMITIVE) {
                index++;
                // convert backend seconds values to milliseconds
                interval = to_uint(payload + token[index].start,
                                            (size_t) token[index].end - token[index].start) * 1000;
                interval = interval < MAX_INTERVAL && interval > 0 ? interval : MAX_INTERVAL;
                EDEBUG_PRINTF("interval: %dms\r\n", interval);
            } else {
                print_token("unknown key:", payload, &token[index]);
                index++;
            }
        }
    } else {
        errors |= E_JSON_FAILED;
    }

    free(token);
}

