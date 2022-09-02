/*
 * 2021.12.16
 * File originally from https://github.com/IamAmitE/FernetCpp/ .
 * Modified to fit Crypt++ 6.0 (latest was 8.6).
 * Modified again to have variable names match the python fernet.py script.
 */

#include "fernet.h"

Fernet::Fernet() {
    if (DEBUG) { printf("freezer_provision_key [%s]\n", freezer_provision_key.c_str()); }
}

// Just to clean up numbers a bit by padding 0's
std::string Fernet::padTo(int i, const size_t num, const char paddingChar = '0')
{
    std::string str = std::to_string(i);
    if(num > str.size())
        str.insert(0, num - str.size(), paddingChar);

    return str;
}

// Handy utility function to see what's happening
void Fernet::dump_bytes(my_byte data[], size_t len) {
    if (!DEBUG) return;

    std::cout << "Length of bytes: " << len << std::endl;
    for(unsigned int i=0; i<len; i++) {
        my_byte chr = my_byte(data[i]);
        std::cout << padTo(i, 2, '0') << ") " << " 0x" << std::hex << (int)chr << std::dec << std::endl;
    }
}

// This comes from:
// https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
// But is modified.
std::string Fernet::base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    size_t len = in.length();
    unsigned int i = 0;
    for (i = 0; i < len; i++) {
        unsigned char c = in[i];
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    // Modified
    switch (out.size() % 4) {
    case 2:
        out = out + std::string("==");
        break;
    case 3:
        out = out + std::string("=");
        break;
    default:
        break;
    }
    return out;
}

// This comes from:
// https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
std::string Fernet::base64_decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    unsigned int i;
    for (i = 0; i < 64; i++) T[base64_url_alphabet[i]] = i;

    int val = 0, valb = -8;
    for (i = 0; i < in.length(); i++) {
        unsigned char c = in[i];
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Coverts the long long time into 8 bytes that go into the token
std::string Fernet::long_long_to_big_endian(unsigned long long num) {
    std::vector<unsigned char> bigEndian;
    for (int i = 7; i >= 0; i--) {
        // std::cout << "HO(" << i << "): [" << ((num >> (8*i)) & 0xff) << "]" << std::endl;
        bigEndian.push_back((num >> (8 * i)) & 0xff);
    }
    return std::string(bigEndian.begin(), bigEndian.end());
}

// The opposite direction
// https://stackoverflow.com/questions/4142251/convert-array-of-8-bytes-to-signed-long-in-c
unsigned long long Fernet::big_endian_to_long_long(std::string num) {
    unsigned long long recovered = 0;
    for (int i = 0; i <= 7; i++) {
        // std::cout << "HI(" << i << "): [" << ( num[i] & 0xff ) << "]" << std::endl;
        recovered |= ( num[i] & 0xff ) << ((7-i) * 8);
    }
    return recovered;
}

/*
 * The Fernet key is used by both encryption and decryption.
 * This routine checks it for validity and converts it to bytes.
 */
bool Fernet::decode_fernet_key(std::string fernet_key) {
    if ( fernet_key.empty() ) {
        std::cout << "*** Error: No Fernet key passed" << std::endl;
        return false;
    }

    std::string decoded_key = base64_decode(fernet_key);
    if (decoded_key.length() != 32) {
        // throw std::invalid_argument("Fernet encryption key must be 32 bytes.");
        std::cout << "*** Error: Fernet encryption key must be 32 bytes." << std::endl;
        return false;
    }
    std::string signing_key = decoded_key.substr(0, 16); // The first 16 bytes are the signing_key
    std::string encryption_key = decoded_key.substr(16, 16); // The final 16 bytes are the aes key

    // Convert strings to bytes
    for (int i = 0; i < 16; i++) {
        signing_key_bytes[i] = my_byte(signing_key[i]);
        encryption_key_bytes[i] = my_byte(encryption_key[i]);
    }
    return true;
}

/*
 * Reference Fernet from Python's cryptography:
 * /usr/lib/python3/dist-packages/cryptography/fernet.py
 * /home/anthony/.local/lib/python3.8/site-packages/cryptography/
 */
std::string Fernet::fernet_encrypt(std::string message, std::string fernet_key, unsigned long long time) {
    // Deal with the fernet key
    if (! decode_fernet_key(fernet_key)) {
        return "";
    }

    // Generate a randomized block of 16 bytes suitable for cryptography
    CryptoPP::AutoSeededRandomPool rnd;
    auto iv = CryptoPP::SecByteBlock(0x00, 16);
    rnd.GenerateBlock(iv, 16);

    // Handle the time
    if (time == 0) {
        time = current_time();
    }
    std::string time_string = long_long_to_big_endian(time);
    if (DEBUG) { std::cout << "Time [" << time << "] TimeString [" << time_string << "]" << std::endl; }

    // Perform AES encryption.
    // In python, this is handled by Cipher()

    std::string ciphertext;

    CryptoPP::AES::Encryption aesEncryption(encryption_key_bytes, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(message.c_str()), message.length());
    stfEncryptor.MessageEnd();
    if (DEBUG) { printf("ciphertext(%d): [%s]\n", int(ciphertext.length()), ciphertext.c_str()); }

    // construct basic_parts string in preparation for HMAC

    std::string basic_parts = std::string("\x80" + time_string + std::string(reinterpret_cast<const char*>(iv.data()), iv.size()) + ciphertext);
    if (DEBUG) { printf("basic_parts(%d): [%s]\n", int(basic_parts.length()), basic_parts.c_str()); }

    // generate HMAC

    // Convert basic_parts into bytes
    auto basic_parts_bytes = CryptoPP::SecByteBlock(0x00, basic_parts.length());
    for (unsigned int i = 0; i < basic_parts.length(); i++) {
        basic_parts_bytes[i] = basic_parts[i];
    }

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(signing_key_bytes);
    hmac.Update(basic_parts_bytes.data(), basic_parts.size());
    my_byte hmac_digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
    hmac.Final(hmac_digest);

    std::string hmac_digest_string(reinterpret_cast<const char*>(hmac_digest), sizeof(hmac_digest));
    if (DEBUG) { printf("hmac_digest_string(%d): [%s]\n", int(hmac_digest_string.length()), hmac_digest_string.c_str()); }

    return base64_encode(basic_parts + hmac_digest_string);
}

// Overloaded for convenience
std::string Fernet::fernet_encrypt(std::string message) {
    return fernet_encrypt(message, freezer_provision_key, 0);
}

// The original example code didn't supply a decrypt function, so this is all new
// and based upon the python code.
//
// Allowing ttl to be negative because it helps with unit tests.
std::string Fernet::fernet_decrypt(std::string token, std::string fernet_key, unsigned long long ttl) {
    // Deal with the fernet key
    if (! decode_fernet_key(fernet_key)) {
        return "";
    }

    // Decode the token and convert to bytes
    std::string decoded_token = base64_decode(token);
    size_t decoded_length = decoded_token.length();
    my_byte decoded_token_bytes[decoded_length];
    for (unsigned int i = 0; i < decoded_length; i++) {
        decoded_token_bytes[i] = my_byte(decoded_token[i]);
    }
    dump_bytes(decoded_token_bytes, decoded_length);

    // Ensure the first byte is 0x80, or it's a corrupt token
    if ( decoded_token_bytes[0] != 0x80 ) {
        std::cout << "*** Error: Improper token" << std::endl;
        return "";
    }

    // The next 8 bytes represents the timestamp.
    // In python, the timestamp is sent as an int into _decrypt_data() to see valid.
    my_byte timestamp_bytes[8];
    std::copy(decoded_token_bytes + 1, decoded_token_bytes + 9, timestamp_bytes);

    // Extract the token_creation_time to a usable form
    dump_bytes(timestamp_bytes, 8);
    std::string time_string(reinterpret_cast<const char *>(timestamp_bytes),8);
    if (DEBUG) { std::cout << "TimeString [" << time_string << "]" << std::endl; }
    unsigned long long token_creation_time = big_endian_to_long_long(time_string);
    if (DEBUG) { std::cout << "Time [" << token_creation_time << "]" << std::endl; }

    // Check the time-to-live, i.e. the expiration of the token.
    // ttl is the number of seconds old a message may be for it to be valid.
    if (ttl != 0) {
        unsigned long long now = current_time();
        if (DEBUG) { std::cout << "Now [" << now << "]" << std::endl; }
        if (token_creation_time + ttl < now) {
            std::cout << "*** Error: Token has expired" << std::endl;
            return "";
       }
    }

    // _verify_signature()

    // Separate into parts
    my_byte iv_bytes[16];
    std::copy(decoded_token_bytes + 9, decoded_token_bytes + 9 + 16, iv_bytes);
    dump_bytes(iv_bytes, 16);
    size_t ciphertext_length = decoded_length - 25 - 32;
    my_byte ciphertext_bytes[ciphertext_length];
    std::copy(decoded_token_bytes + 25, decoded_token_bytes + decoded_length - 32, ciphertext_bytes);
    dump_bytes(ciphertext_bytes, ciphertext_length);

    // Perform AES decryption.
    // In python, this is handled by Cipher()

    std::string recovered = "";

    CryptoPP::AES::Decryption aesDecryption(encryption_key_bytes, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv_bytes);

    try {
        CryptoPP::StringSource s(ciphertext_bytes, ciphertext_length, true,
            new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::StringSink(recovered)));
    }
    catch(CryptoPP::InvalidCiphertext &e)
    {
        std::cout << "*** Error: Invalid Cipher Text" << std::endl;
        std::cout << e.what() << std::endl;
        std::cout << "Length: " << ciphertext_length << std::endl;
    }

    if (DEBUG) {
        printf("\n-------------- fernet_decrypt -------------\n");
        printf("token(%d): [%s]\n", int(token.length()), token.c_str());
        printf("recovered(%d): [%s]\n", int(recovered.length()), recovered.c_str());
    }

    return recovered;
}

// Overloaded for convenience
std::string Fernet::fernet_decrypt(std::string token) {
    return fernet_decrypt(token, freezer_provision_key, 0);
}

unsigned long long Fernet::current_time() {
    std::chrono::seconds ms = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch());
    unsigned long long time = ms.count();
    return time;
}

