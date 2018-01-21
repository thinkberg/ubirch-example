#include <mbed.h>
#include <mbedtls/sha256.h>
#include <edebug.h>
#include <BME280/BME280.h>
#include <mbed-os-quectel-m66/source/M66Interface.h>
#include <mbed-http/source/http_request.h>
#include <ubirch-mbed-sd-storage/source/SDStorage.h>
#include <ubirch-mbed-nacl-cm0/source/nacl/armnacl.h>
#include <msgpack/msgpack.h>
#include <mbed-os/features/mbedtls/inc/mbedtls/base64.h>
#include "config.h"

#define VERSION "1.0"

#ifdef DEMO
#define UHTTP_PORT 80
#define UHTTP_HOST "unsafe.api.ubirch.demo.ubirch.com"
#define UHTTP_URL "http://unsafe.api.ubirch.demo.ubirch.com/api/avatarService/v1/device/update/mpack"
#define UKEY_SERVICE_PORT 80
#define UKEY_SERVICE_HOST "unsafe.key.demo.ubirch.com"
#define UKEY_SERVICE_URL  "http://unsafe.key.demo.ubirch.com/api/keyService/v1/pubkey"
#else
#define UHTTP_PORT 80
#define UHTTP_HOST "unsafe.api.ubirch.dev.ubirch.com"
#define UHTTP_URL "http://unsafe.api.ubirch.dev.ubirch.com/api/avatarService/v1/device/update/mpack"
#define UKEY_SERVICE_PORT 80
#define UKEY_SERVICE_HOST "unsafe.key.dev.ubirch.com"
#define UKEY_SERVICE_URL  "http://unsafe.key.dev.ubirch.com/api/keyService/v1/pubkey"
#endif

#define PRI_KEY_PATH "/ub/prk.bin"
#define PUB_KEY_PATH "/ub/puk.bin"

DigitalOut led(LED1);
int ledEvent;
Thread ledEventThread;
EventQueue ledEventQueue;

SDStorage sd(PTE3, PTE1, PTE2, PTE4);
static unsigned char pub[crypto_sign_PUBLICKEYBYTES];
static unsigned char pri[crypto_sign_SECRETKEYBYTES];

BME280 sensor(I2C_SDA, I2C_SCL);
M66Interface modem(GSM_UART_TX, GSM_UART_RX, GSM_PWRKEY, GSM_POWER);

int errors = 0;
int interval = 300 * 1000;
uint32_t uuid[4];
unsigned char lastSignature[crypto_sign_BYTES];

char *process_response(char *response, size_t responseLen,
                       unsigned char key[crypto_sign_PUBLICKEYBYTES],
                       unsigned char signature[crypto_sign_BYTES]);

void process_payload(char *payload);

int ed25519_sign(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]) {
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + 32];
    crypto_sign(signedMessage, &signedLength, (const unsigned char *) buf, (crypto_uint16) len, pri);
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    free(signedMessage);
    return 0;
}

TCPSocket *open(const char *host, const uint16_t port) {
    nsapi_error_t error;
    TCPSocket *socket = new TCPSocket;
    socket->set_timeout(0);

    if ((error = socket->open(&modem)) != NSAPI_ERROR_OK) {
        EDEBUG_PRINTF("socket: open failed: %d\r\n", error);
        delete socket;
        return NULL;
    }

    if ((error = socket->connect(host, port)) != NSAPI_ERROR_OK) {
        EDEBUG_PRINTF("socket: connect failed: %d\r\n", error);
        socket->close();
        delete socket;
        return NULL;
    }

    return socket;
}

void responseHandler(const char *data, size_t length) {
    unsigned char serverKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char serverSig[crypto_sign_BYTES];

    char *payload = process_response(const_cast<char *>(data), length, serverKey, serverSig);
    process_payload(payload);
}

int transmit(const char *host, const int port, const char *url, const unsigned char *data, const size_t length) {
    TCPSocket *socket = open(host, static_cast<const uint16_t>(port));
    if (socket != NULL) {
        HttpRequest *request = new HttpRequest(socket, HTTP_POST, url, responseHandler);
        request->set_header("Content-Type", "application/json");
        HttpResponse *response = request->send(data, length);
        int status = 0;
        if (response && response->get_status_code()) {

            switch (response->get_status_code()) {
                case 202:
                case 200:
                    EDEBUG_PRINTF("STATUS 'OK'\r\n");
                    break;
                default:
                    EDEBUG_PRINTF("STATUS %d\r\n", response->get_status_code());
                    status = response->get_status_code();
                    break;
            }
        } else {
            EDEBUG_PRINTF("HTTP FAILED\r\n");
            status = -2;
        }
        delete request;
        socket->close();
        return status;
    }
    return -1;
}

int register_key() {
    // get the time of creation
    time_t timestamp = time(NULL);
    struct tm *tm1 = gmtime(&timestamp);
    static const char *const timeStamp_template = "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ"; //“2017-05-09T10:25:41.836Z”

    // make a  time string in ISO 8601 format
    int time_size = snprintf(NULL, 0, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
                             tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    char *created = new char[time_size + 1];
    sprintf(created, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    EDEBUG_PRINTF("KEY: created = %s\r\n", created);

    // set the validation from to the time of creation
    char *validNotBefore = new char[time_size + 1];
    sprintf(validNotBefore, timeStamp_template, tm1->tm_year + 1900, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    //TODO same as created time
    EDEBUG_PRINTF("KEY: validNotBefore = %s\r\n", validNotBefore);

    char *validNotAfter = new char[time_size + 1];
    sprintf(validNotAfter, timeStamp_template, tm1->tm_year + 1900 + 1, tm1->tm_mon + 1, tm1->tm_mday,
            tm1->tm_hour, tm1->tm_min, tm1->tm_sec, 0);
    //TODO same as created time + 1 years
    EDEBUG_PRINTF("KEY: validNotAfter = %s\r\n", validNotAfter);

    // make a string out of the device id
    char hwDeviceId[34];
    int idx = 0;
    for (unsigned int i = 0; i < sizeof(uuid); i++) {
        if (idx == 16) hwDeviceId[idx++] = '-';
        sprintf(hwDeviceId + idx, "%02x", ((uint8_t *) uuid)[i]);
        idx += 2;
    }
    EDEBUG_PRINTF("hwDeviceId = %s\r\n", hwDeviceId);

    char pubKeyEncoded[45];
    size_t pkelen;
    EDEBUG_PRINTF("base64: %d, %d\r\n",
                  mbedtls_base64_encode(reinterpret_cast<unsigned char *>(pubKeyEncoded), 45, &pkelen, pub,
                                        sizeof(pub)), pkelen);


    char *pubKeyId = {""};
    char *algorithm = {"ECC_ED25519"};
    char *previousPubKeyId = {""};
    char *previousPubKeySignature = {""};

    // create the JSON for pubKeyInfo
    static const char *const pubKeyInfo_template = "{"
            "\"hwDeviceId\":\"%s\","
            "\"pubKey\":\"%s\","
            "\"pubKeyId\":\"%s\","
            "\"algorithm\":\"%s\","
            "\"previousPubKeyId\":\"%s\","
            "\"created\":\"%s\","
            "\"validNotBefore\":\"%s\","
            "\"validNotAfter\":\"%s\""
            "}";

    int pubKeyInfoSize = snprintf(NULL, 0, pubKeyInfo_template, hwDeviceId, pubKeyEncoded, pubKeyId, algorithm,
                                  previousPubKeyId, created, validNotBefore, validNotAfter);
    char *pubKeyInfo = new char[pubKeyInfoSize + 1];
    sprintf(pubKeyInfo, pubKeyInfo_template, hwDeviceId, pubKeyEncoded, pubKeyId, algorithm,
            previousPubKeyId, created, validNotBefore, validNotAfter
    );
    EDEBUG_PRINTF("pubKeyInfo = %s\r\n", pubKeyInfo);


    // sign PubKeyInfo
    unsigned char signature[crypto_sign_BYTES];
    ed25519_sign(pubKeyInfo, static_cast<size_t>(pubKeyInfoSize), signature);
    char signatureEncoded[89];
    size_t selen;
    EDEBUG_PRINTF("base64: %d\r\n",
                  mbedtls_base64_encode(reinterpret_cast<unsigned char *>(signatureEncoded), 89, &selen, signature,
                                        sizeof(signature)));

    static const char *const message_template = "{"
            "\"pubKeyInfo\":%s,"
            "\"signature\":\"%s\","
            "\"previousPubKeySignature\":\"%s\""
            "}";

    // create the complete JSON
    int messageSize = snprintf(NULL, 0, message_template, pubKeyInfo, signatureEncoded, previousPubKeySignature);
    char *message = new char[messageSize + 1];
    sprintf(message, message_template, pubKeyInfo, signatureEncoded, previousPubKeySignature);
    EDEBUG_PRINTF("message (%u) = %s\r\n", (uint16_t) strlen((const char *) (message)), message);


    transmit(UKEY_SERVICE_HOST, UKEY_SERVICE_PORT, UKEY_SERVICE_URL,
             reinterpret_cast<const unsigned char *>(message), strlen(message));

    // free the memory
    delete (created);
    delete (validNotBefore);
    delete (validNotAfter);
    delete (pubKeyInfo);

    return 0;
}

int generate(bool force) {
    memset(pri, 0, sizeof(pri));
    memset(pub, 0, sizeof(pub));

    if (force || !sd.getFileSize(PRI_KEY_PATH) || !sd.getFileSize(PUB_KEY_PATH)) {
        EDEBUG_PRINTF("generating new key pair\r\n");
        crypto_sign_keypair(pri, pub);
        EDEBUG_PRINTF("done.\r\n");

        sd.write(PRI_KEY_PATH, pri, sizeof(pri), 1);
        sd.write(PUB_KEY_PATH, pub, sizeof(pub), 1);
        register_key();
    } else {
        if (sd.read(PRI_KEY_PATH, pri, sizeof(pri), 1) == sizeof(pri)) {
            EDEBUG_PRINTF("failed to load "
                                  PRI_KEY_PATH
                                  "\r\n");
        }
        if (sd.read(PUB_KEY_PATH, pub, sizeof(pub), 1) == sizeof(pri)) {
            EDEBUG_PRINTF("failed to load "
                                  PUB_KEY_PATH
                                  "\r\n");
        };
    }
    EDEBUG_HEX("PUB", pub, sizeof(pub));
    return 0;
}

int pack(msgpack_sbuffer *sbuf, int timestamp, int temperature, int humidity, int pressure) {
    msgpack_packer pk = {};
    msgpack_packer_init(&pk, sbuf, msgpack_sbuffer_write);

    // prepare message header
    // data is encoded in message pack format (array)
    msgpack_pack_array(&pk, 7);

    // 1 - protocol version
    msgpack_pack_raw(&pk, 3);
    msgpack_pack_raw_body(&pk, "4.0", 3);

    // 2 - software version
    const char *softwareVersion = "v0.8";
    msgpack_pack_raw(&pk, strlen(softwareVersion));
    msgpack_pack_raw_body(&pk, softwareVersion, strlen(softwareVersion));

    // 3 - hardware serial
    msgpack_pack_raw(&pk, 16);
    msgpack_pack_raw_body(&pk, uuid, 16);

    // 4 last signature hash
    msgpack_pack_raw(&pk, 64);
    msgpack_pack_raw_body(&pk, lastSignature, 64);

    // 5 - map of measurements [time: value]
    msgpack_pack_map(&pk, 1);

    // Append the time stamp as the key
    msgpack_pack_int32(&pk, timestamp);
    // map of three sensors
    msgpack_pack_map(&pk, 4);
    msgpack_pack_raw(&pk, strlen("i"));
    msgpack_pack_raw_body(&pk, "i", strlen("i"));
    msgpack_pack_int(&pk, interval/1000);

    msgpack_pack_raw(&pk, strlen("temperature"));
    msgpack_pack_raw_body(&pk, "temperature", strlen("temperature"));
    msgpack_pack_int(&pk, temperature);
    msgpack_pack_raw(&pk, strlen("humidity"));
    msgpack_pack_raw_body(&pk, "humidity", strlen("humidity"));
    msgpack_pack_int(&pk, humidity);
    msgpack_pack_raw(&pk, strlen("pressure"));
    msgpack_pack_raw_body(&pk, "pressure", strlen("pressure"));
    msgpack_pack_int(&pk, pressure);

    // 6 - error state
    msgpack_pack_int(&pk, errors);
    errors = 0;

    // 7 - the signature (hash data, then sign)
    unsigned char hash[32];
    mbedtls_sha256_context sha256 = {};
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0);
    mbedtls_sha256_update(&sha256, (const unsigned char *) sbuf->data, sbuf->size);
    mbedtls_sha256_finish(&sha256, hash);

    /* Create a signature of the hash*/
    ed25519_sign(reinterpret_cast<const char *>(hash), 32, lastSignature);
    msgpack_pack_raw(&pk, 64);
    msgpack_pack_raw_body(&pk, lastSignature, 64);

    return 0;
}

void blink() {
    led = !led;
}

void signal(int ms) {
    if (ledEvent != -1) ledEventQueue.cancel(ledEvent);
    if (!ms) {
        led = 0;
        return;
    }

    ledEvent = ledEventQueue.call_every(ms, blink);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-noreturn"

int main() {
    EDEBUG_SETUP(NULL);
    EDEBUG_PRINTF("ubirch-example "
                          VERSION
                          "\r\n");

    ledEventThread.start(callback(&ledEventQueue, &EventQueue::dispatch_forever));

    // device UUID
    uuid[0] = SIM->UIDH;
    uuid[1] = SIM->UIDMH;
    uuid[2] = SIM->UIDML;
    uuid[3] = SIM->UIDL;
    EDEBUG_HEX("UUID:", (uint8_t *) uuid, sizeof(uuid));

    sd.init();
    sensor.initialize();

    signal(50);
    while (modem.connect(CELL_APN, CELL_USER, CELL_PWD)) {
        Thread::wait(5000);
        EDEBUG_PRINTF("modem connect failed, retry...\r\n");
    }
    time_t timestamp;
    modem.getUnixTime(&timestamp);
    set_time(timestamp);

    signal(80);
    generate(false);
    signal(0);

    memset(lastSignature, 0, 64);
    msgpack_sbuffer sbuf = {};
    msgpack_sbuffer_init(&sbuf);

    while (true) {
        signal(1000);

        time(&timestamp);
        const int temperature = (int) (sensor.getTemperature() * 100);
        const int humidity = (int) (sensor.getHumidity() * 100);
        const int pressure = (int) sensor.getPressure();

        EDEBUG_PRINTF("time = %d\r\n", timestamp);
        EDEBUG_PRINTF("temp = %d\r\n", temperature);
        EDEBUG_PRINTF("humi = %d\r\n", humidity);
        EDEBUG_PRINTF("pres = %d\r\n", pressure);

        msgpack_sbuffer_clear(&sbuf);
        pack(&sbuf, timestamp, temperature, humidity, pressure);

        EDEBUG_DUMP("MSG", (uint8_t *) sbuf.data, sbuf.size);
        transmit(UHTTP_HOST, UHTTP_PORT, UHTTP_URL, reinterpret_cast<const unsigned char *>(sbuf.data), sbuf.size);

        EDEBUG_PRINTF("Waiting ...\r\n");
        signal(0);
        Thread::wait((uint32_t) interval);
    }
}

#pragma GCC diagnostic pop
