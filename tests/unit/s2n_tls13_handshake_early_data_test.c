/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_array.h"
#include "utils/s2n_mem.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_handshake_transcript.c"
#include "tls/s2n_tls13_handshake.c"

#define S2N_SECRET_TYPE_COUNT 5

const uint8_t empty_secret[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
message_type_t empty_handshake[S2N_MAX_HANDSHAKE_LENGTH] = { 0 };

int main()
{
    BEGIN_TEST();

    /* Test early data encryption */
    {
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  generate resumption secret "tls13 resumption":
         *#
         *#    PRK (32 octets):  7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
         *#       da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
         *#
         *#    hash (2 octets):  00 00
         *#
         *#    info (22 octets):  00 20 10 74 6c 73 31 33 20 72 65 73 75 6d 70 74
         *#       69 6f 6e 02 00 00
         *#
         *#    expanded (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
         *#       a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         */
        S2N_BLOB_FROM_HEX(psk_secret, "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c \
                  a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  construct a NewSessionTicket handshake message:
         *#
         *#    NewSessionTicket (205 octets):  04 00 00 c9 00 00 00 1e fa d6 aa
         *#       c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
         *#       00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
         *#       49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
         *#       72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
         *#       27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
         *#       a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
         *#       5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
         *#       17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
         *#       5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
         *#       04 00 00 04 00
         */
        /* Skip past the message type, message size, ticket lifetime,
         * ticket age add, nonce, and ticket size:
         *                                     04 00 00 c9 00 00 00 1e fa d6 aa
         *        c5 02 00 00 00 b2
         */
        S2N_BLOB_FROM_HEX(psk_identity,
                "2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00 \
                  00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c \
                  49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11 \
                  72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 \
                  27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 \
                  a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c \
                  5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 \
                  17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 \
                  5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57");
        /* Skip past the total extensions size, early data extension type,
         * and early data extension size:                         00 08 00 2a 00
         *        04
         */
        const uint32_t max_early_data = 0x00000400;

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send handshake record:
         *#
         *#    payload (512 octets):  01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
         *#       93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
         *#       48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
         *#       09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         *#       00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
         *#       26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
         *#       6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
         *#       00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         *#       03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         *#       02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
         *#       00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
         *#       ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
         *#       82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
         *#       1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
         *#       37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
         *#       90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
         *#       ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
         *#       e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
         *#       cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
         *#       ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
         */
        S2N_BLOB_FROM_HEX(client_hello_msg,
                "01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff \
                  93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76 \
                  48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 \
                  09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 \
                  00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 \
                  26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34 \
                  6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00 \
                  00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 \
                  03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 \
                  02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 \
                  00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 \
                  ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 \
                  82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 \
                  1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 \
                  37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 \
                  90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 \
                  ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d \
                  e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa \
                  cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d \
                  ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d")
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (517 octets):  16 03 01 02 00 01 00 01 fc 03 03 1b
         *#       c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49
         *#       d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00
         *#       01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         *#       00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         *#       01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d
         *#       96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1
         *#       8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         *#       04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         *#       01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
         *#       00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59
         *#       ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb
         *#       33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc
         *#       55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3
         *#       6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66
         *#       4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29
         *#       51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72
         *#       14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6
         *#       21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93
         *#       4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca
         *#       3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f
         *#       9d
         */
        S2N_BLOB_FROM_HEX(ch_record, "16 03 01 02 00 01 00 01 fc 03 03 1b \
                  c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 \
                  d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 \
                  01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 \
                  00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 \
                  01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d \
                  96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 \
                  8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e \
                  04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 \
                  01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 \
                  00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 \
                  ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb \
                  33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc \
                  55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 \
                  6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 \
                  4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 \
                  51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 \
                  14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 \
                  21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 \
                  4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca \
                  3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f \
                  9d");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  extract secret "early":
         *#
         *#    salt:  0 (all zero octets)
         *#
         *#    IKM (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5
         *#       85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         *#
         *#    secret (32 octets):  9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20
         *#       bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c
         */
        S2N_BLOB_FROM_HEX(early_secret,
                "9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 \
                  bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  derive write traffic keys for early application data:
         *#
         *# PRK (32 octets):  3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e
         *#       aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
         *#
         *# key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
         *#
         *# key expanded (16 octets):  92 02 05 a5 b7 bf 21 15 e6 fc 5c 29 42
         *#       83 4f 54
         *#
         *# iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
         *#
         *# iv expanded (12 octets):  6d 47 5f 09 93 c8 e5 64 61 0d b2 b9
         */
        S2N_BLOB_FROM_HEX(iv, "6d 47 5f 09 93 c8 e5 64 61 0d b2 b9");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send application_data record:
         *#
         *#    payload (6 octets):  41 42 43 44 45 46
         */
        S2N_BLOB_FROM_HEX(payload, "41 42 43 44 45 46");
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (28 octets):  17 03 03 00 17 ab 1d f4 20 e7 5c 45
         *#       7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0
         */
        S2N_BLOB_FROM_HEX(complete_record, "17 03 03 00 17 ab 1d f4 20 e7 5c 45 \
                  7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0");

        /* Test client early data encryption against known client outputs */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->server_protocol_version = S2N_TLS13;
            client_conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void **) &psk));
            psk->hmac_alg = S2N_HMAC_SHA256;
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, max_early_data, 0x13, 0x01));
            client_conn->secure->cipher_suite = psk->early_data_config.cipher_suite;

            /* Rewrite early secret with known early secret. */
            EXPECT_SUCCESS(s2n_dup(&early_secret, &psk->early_secret));

            /* Rewrite hashes with known ClientHello */
            EXPECT_SUCCESS(s2n_conn_update_handshake_hashes(client_conn, &client_hello_msg));

            EXPECT_OK(s2n_tls13_secrets_update(client_conn));
            EXPECT_OK(s2n_tls13_key_schedule_update(client_conn));

            /* Check early secret secret set correctly */
            EXPECT_EQUAL(client_conn->secrets.extract_secret_type, S2N_EARLY_SECRET);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secrets.version.tls13.extract_secret, early_secret.data, early_secret.size);

            /* Check IV calculated correctly */
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure->client_implicit_iv, iv.data, iv.size);

            /* Check payload encrypted correctly */
            EXPECT_OK(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &payload));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), complete_record.size);
            EXPECT_BYTEARRAY_EQUAL(client_conn->out.blob.data, complete_record.data, complete_record.size);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

/* The known ClientHello uses the x25519 curve,
 * which the S2N server won't accept if the EVP APIs are not supported */
#if EVP_APIS_SUPPORTED
        /* Test server early data encryption with known client inputs */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));

            DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
            psk->type = S2N_PSK_TYPE_RESUMPTION;
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_identity.data, psk_identity.size));
            EXPECT_SUCCESS(s2n_psk_set_secret(psk, psk_secret.data, psk_secret.size));
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, max_early_data, 0x13, 0x01));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, psk));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));

            s2n_blocked_status blocked = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), END_OF_EARLY_DATA);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &complete_record));

            DEFER_CLEANUP(struct s2n_blob actual_payload = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&actual_payload, payload.size));
            int r = s2n_recv(server_conn, actual_payload.data, actual_payload.size, &blocked);
            EXPECT_EQUAL(r, payload.size);
            EXPECT_BYTEARRAY_EQUAL(actual_payload.data, payload.data, payload.size);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
#endif
    };

    END_TEST();
}
