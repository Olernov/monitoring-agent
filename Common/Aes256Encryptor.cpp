/// Project : Nectus 
/// Component : Monitoring Linux Service
/// Copyright : Virtual Console, LLC  2001-2018 
/// Author : Oleg Smirnov
/// Description: Contains definition of CEncryptor class

#include "stdafx.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "Aes256Encryptor.h"

//////////////////////////////////////////////////////////////////////////
CAes256Encryptor::CAes256Encryptor(const std::string& givenKey)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    assert(givenKey.size() > 0);
    if (givenKey.size() >= KEY_LENGTH_BYTES)
    {
        // If the key is 256-bit or even longer then take only first 256 bits
        std::copy(givenKey.begin(), givenKey.begin() + KEY_LENGTH_BYTES, m_key.begin());
    }
    else
    {
        // If the key is too short then copy it several times to fill the whole key buffer
        auto copyTimes = KEY_LENGTH_BYTES / givenKey.size(); // integers division
        for (auto i = 0; i < copyTimes; ++i)
        {
            std::copy(givenKey.begin(), givenKey.end(), m_key.begin() + givenKey.size() * i);
        }
        // If there is still some space then copy a part of the key
        int leftover = KEY_LENGTH_BYTES % givenKey.size();
        if (leftover > 0)
        {
            std::copy(givenKey.begin(), givenKey.begin() + leftover, 
                m_key.begin() + copyTimes * givenKey.size());
        }
    }
}

//////////////////////////////////////////////////////////////////////////
CAes256Encryptor::~CAes256Encryptor()
{
    // Remove error strings
    ERR_free_strings();
}

//////////////////////////////////////////////////////////////////////////
void CAes256Encryptor::SetErrorDescription()
{
    m_errorDescription.clear();
    unsigned long errCode;
    while ((errCode = ERR_get_error()) != 0)
    {
        if (!m_errorDescription.empty())
        {
            m_errorDescription += '\n';
        }
        m_errorDescription += ERR_error_string(errCode, nullptr);
    }
}

//////////////////////////////////////////////////////////////////////////
bool CAes256Encryptor::Encrypt(const ByteVector& plain, uint32_t requestNumber, ByteVector& encrypted)
{
    EVP_CIPHER_CTX *ctx = nullptr;

    // Create and initialise the context 
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        SetErrorDescription();
        return false;
    }

    // Initialise the encryption operation. 
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        SetErrorDescription();
        return false;
    }

    // Set IV length if default 12 bytes (96 bits) is not appropriate 
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, INIT_VECTOR_LENGTH_BYTES, nullptr) != 1)
    {
        SetErrorDescription();
        return false;
    }

    // Reserve enough space for the ecnrypted buffer 
    encrypted.resize(INIT_VECTOR_LENGTH_BYTES + TAG_LENGTH_BYTES + plain.size() + EVP_MAX_BLOCK_LENGTH); 
    
    // Generate initialisation vector from request number and print it in front of the encrypted buffer
    snprintf(reinterpret_cast<char*>(encrypted.data()), INIT_VECTOR_LENGTH_BYTES, "%x", requestNumber);

    // Initialise key and IV 
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, m_key.data(), encrypted.data()) != 1) 
    {
        SetErrorDescription();
        return false;
    }

    int len = 0, encryptedLen = INIT_VECTOR_LENGTH_BYTES + TAG_LENGTH_BYTES;
    
    // Obtain the encrypted output
    if (!plain.empty())
    {
        if (EVP_EncryptUpdate(ctx, &encrypted[encryptedLen], &len, plain.data(), 
            static_cast<int>(plain.size())) != 1)
        {
            SetErrorDescription();
            return false;
        }
        encryptedLen += len;
    }

    // Finalise the encryption. Normally ciphertext bytes may be written at
    // this stage, but this does not occur in GCM mode  
    if (EVP_EncryptFinal_ex(ctx, &encrypted[encryptedLen], &len) != 1)
    {
        SetErrorDescription();
        return false;
    }

    encryptedLen += len;
    encrypted.resize(encryptedLen);

    // Write the tag in front of buffer after the IV
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH_BYTES, &encrypted[INIT_VECTOR_LENGTH_BYTES]) != 1)
    {
        SetErrorDescription();
        return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return true;                            
}

bool CAes256Encryptor::Decrypt(ByteVector& encrypted, ByteVector& plain)
{
    EVP_CIPHER_CTX *ctx = nullptr;

    // Create and initialise the context 
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        SetErrorDescription();
        return false;
    }

    // Initialise the decryption operation. 
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm() , nullptr, nullptr, nullptr))
    {
        SetErrorDescription();
        return false;
    }

    // Set IV length. Not necessary if this is 12 bytes (96 bits) 
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, INIT_VECTOR_LENGTH_BYTES, nullptr))
    {
        SetErrorDescription();
        return false;
    }

    // Initialise key and IV 
    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, m_key.data(), 
        encrypted.data())) // IV is placed in front of the buffer
    {
        SetErrorDescription();
        return false;
    }

    int len = 0, plainLen = 0;
    plain.resize(encrypted.size() + EVP_MAX_BLOCK_LENGTH);  // reserve enough space

    // Obtain the decrypted data if encrypted is not empty
    if (encrypted.size() > INIT_VECTOR_LENGTH_BYTES + TAG_LENGTH_BYTES)
    {
        if (!EVP_DecryptUpdate(ctx, &plain[0], &len, &encrypted[INIT_VECTOR_LENGTH_BYTES + TAG_LENGTH_BYTES], 
            static_cast<int>(encrypted.size()) - INIT_VECTOR_LENGTH_BYTES - TAG_LENGTH_BYTES))
        {
            SetErrorDescription();
            return false;
        }
        plainLen = len;
    }

    // Set expected tag value. Works in OpenSSL 1.0.1d and later 
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH_BYTES, 
        reinterpret_cast<void*>(&encrypted[INIT_VECTOR_LENGTH_BYTES])))
    {
        SetErrorDescription();
        return false;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy. 
    int ret = EVP_DecryptFinal_ex(ctx, &plain[len], &len);

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        // Success 
        plainLen += len;
        plain.resize(plainLen);
        return true;
    }
    else
    {
        // Verify failed 
        return false;
    }
}
