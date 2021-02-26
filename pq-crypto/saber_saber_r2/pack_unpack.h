#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#include <stdio.h>
#include <stdint.h>
#include "SABER_params.h"

void POLT2BS(uint8_t bytes[SABER_SCALEBYTES_KEM], const uint16_t data[SABER_N]);
void BS2POLT(const uint8_t bytes[SABER_SCALEBYTES_KEM], uint16_t data[SABER_N]);

void POLVECq2BS(uint8_t bytes[SABER_POLYVECBYTES], const uint16_t data[SABER_L][SABER_N]);
void POLVECp2BS(uint8_t bytes[SABER_POLYVECCOMPRESSEDBYTES], const uint16_t data[SABER_L][SABER_N]);

void BS2POLVECq(const uint8_t bytes[SABER_POLYVECBYTES], uint16_t data[SABER_L][SABER_N]);
void BS2POLVECp(const uint8_t bytes[SABER_POLYVECCOMPRESSEDBYTES], uint16_t data[SABER_L][SABER_N]);

void BS2POLmsg(const uint8_t bytes[SABER_KEYBYTES], uint16_t data[SABER_N]);
void POLmsg2BS(uint8_t bytes[SABER_KEYBYTES], const uint16_t data[SABER_N]);

#endif
