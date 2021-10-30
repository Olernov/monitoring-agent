/// Project : Nectus 
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019 
/// Author : Oleg Smirnov
/// Description: Contains declaration of CEncryptor class

#pragma once

//////////////////////////////////////////////////////////////////////////
// This class performs encryption and decryption using openSSL library (AES-256 in GCM mode).
// Based on example: https://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
// Class generates initialization vector (IV) based on request number and writes it in front
// of the output buffer. After IV the authentication tag is written to the buffer 
// and then encrypted data.
class CAes256Encryptor
{
public:
    using ByteVector = std::vector<uint8_t>;

    CAes256Encryptor() = delete;

    explicit CAes256Encryptor(const std::string& key);

    ~CAes256Encryptor();

    // Encrypts vector of bytes. Returned value indicates success or failure of the operation
    bool Encrypt(const ByteVector& plain, uint32_t requestNumber, ByteVector& encrypted);
    
    // Decrypts vector of bytes. Returned value indicates success or failure of the operation
    bool Decrypt(ByteVector& encrypted, ByteVector& plain);

    const std::string GetErrorDescription() const { return m_errorDescription; }

private:
    static const int KEY_LENGTH_BYTES = 32;    // Key length = 256 bit
    static const int TAG_LENGTH_BYTES = 16;
    static const int INIT_VECTOR_LENGTH_BYTES = 12; // This size is strongly suggested to avoid additional computation
        // See also: https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
    
    void SetErrorDescription();

    std::array<uint8_t, KEY_LENGTH_BYTES> m_key{};  // Initialize with zeroes
    std::string m_errorDescription;
};

