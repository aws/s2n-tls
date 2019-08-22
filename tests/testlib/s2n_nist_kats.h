/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
 *
 * Modified from PQCgenKAT_kem.c
 * Created by Bassham, Lawrence E (Fed) on 8/29/17.
 * Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 */

#pragma once

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_MARKER_LEN 50
#define NUM_OF_KATS 100

/*
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 */

static inline int FindMarker(FILE *infile, const char *marker)
{
    char line[MAX_MARKER_LEN];
    uint32_t i, len;

    len = (int)strlen(marker);
    if ( len > (MAX_MARKER_LEN - 1) ) {
        len = MAX_MARKER_LEN-1;
    }

    for ( i=0; i<len; i++ ) {
        if ( (line[i] = fgetc(infile)) == EOF ) {
            return -1;
        }
    }
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) ) {
            return 0;
        }

        for ( i=0; i<len-1; i++ ) {
            line[i] = line[i+1];
        }
        if ( (line[len-1] = fgetc(infile)) == EOF ) {
            return -1;
        }
        line[len] = '\0';
    }
}

/*
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 */

static inline int ReadHex(FILE *infile, uint8_t *buf, uint32_t len, const char *str)
{
    int ch;
    int started = 0;
    uint8_t ich;

    if (0 == len) 
    {
        buf[0] = 0x00;
        return 0;
    }

    memset(buf, 0x00, len);

    if (FindMarker(infile, str) == -1)
    {
        return -1;
    }

    while ((ch = fgetc(infile)) != EOF) 
    {
        if (!isxdigit(ch)) {
            if (!started) {
                if (ch == '\n')
                    break;
                else
                    continue;
            } else
                break;
        }
        started = 1;

        if ((ch >= '0') && (ch <= '9')) {
            ich = ch - '0';
        }
        else if ((ch >= 'A') && (ch <= 'F')) {
            ich = ch - 'A' + 10;
        }
        else if ((ch >= 'a') && (ch <= 'f')) {
            ich = ch - 'a' + 10;
        }
        else 
        {
            /* shouldn't ever get here */
            ich = 0;
        }

        for (uint32_t i = 0; i < len - 1; i++)
        {
            buf[i] = (buf[i] << 4) | (buf[i + 1] >> 4);
        }
        buf[len - 1] = (buf[len - 1] << 4) | ich;
    }
 
    return 0;
}

