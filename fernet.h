#pragma once
#ifndef _FERNET_H
#define _FERNET_H

#include "../common/common.h"
#include <vector>
#include <exception>
#include <iostream>             // For cout
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>

// This to get around the missing Crypto++ byte
// https://www.cryptopp.com/wiki/Std::byte#Use_Crypto.2B.2B_byte
typedef unsigned char my_byte;

class Fernet {

private:

    const char base64_url_alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    my_byte signing_key_bytes[16], encryption_key_bytes[16];

    std::string padTo(int i, const size_t num, const char paddingChar);

    void dump_bytes(my_byte data[], size_t len);

    bool decode_fernet_key(std::string fernet_key);

public:

    Fernet();

    std::string fernet_encrypt(std::string message, std::string fernet_key, unsigned long long time = 0);
    std::string fernet_encrypt(std::string message);

    std::string fernet_decrypt(std::string token, std::string fernet_key, unsigned long long ttl = 0);
    std::string fernet_decrypt(std::string token);

    std::string base64_encode(const std::string& in);
    std::string base64_decode(const std::string& in);

    std::string long_long_to_big_endian(unsigned long long num);
    unsigned long long big_endian_to_long_long(std::string num);

    unsigned long long current_time();

    // If you want a token that never expires, set the time to this.
    inline unsigned long long infinite_time() { return ULLONG_MAX; }
};
#endif // _FERNET_H
