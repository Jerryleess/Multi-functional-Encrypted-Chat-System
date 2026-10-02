#include "header.h"
#include "func.h"

using namespace std;

extern const unsigned char PSK_ENC[32] = {
    0x10,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,0x01,
    0x12,0x24,0x36,0x48,0x5a,0x6c,0x7e,0x80,0x91,0xa2,0xb3,0xc4,0xd5,0xe6,0xf7,0x08
};
extern const unsigned char PSK_MAC[32] = {
    0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,
    0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0
};

bool send_all(int fd, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        total += (size_t)n;
    }
    return true;
}

bool recv_all(int fd, void* data, size_t len) {
    unsigned char* p = (unsigned char*)data;
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        total += (size_t)n;
    }
    return true;
}

bool send_frame(int fd, const vector<unsigned char>& payload) {
    uint32_t len = (uint32_t)payload.size();
    uint32_t netlen = htonl(len);
    if (!send_all(fd, &netlen, sizeof(netlen))) return false;
    if (len == 0) return true;
    return send_all(fd, payload.data(), payload.size());
}

bool recv_frame(int fd, vector<unsigned char>& payload) {
    payload.clear();
    uint32_t netlen = 0;
    if (!recv_all(fd, &netlen, sizeof(netlen))) return false;
    uint32_t len = ntohl(netlen);
    if (len > (1024u * 1024u)) return false; // 1MB
    payload.resize(len);
    if (len == 0) return true;
    return recv_all(fd, payload.data(), len);
}

bool hmac_sha256_ossl3(const unsigned char* key, size_t key_len,
                        const unsigned char* data1, size_t data1_len,
                        const unsigned char* data2, size_t data2_len,
                        unsigned char out[32]) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) return false;

    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!mctx) return false;

    // 指定 HMAC 使用的 digest = SHA256
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    bool ok = false;

    size_t out_len = 0;
    if (EVP_MAC_init(mctx, key, key_len, params) != 1) goto cleanup;
    if (data1_len > 0 && EVP_MAC_update(mctx, data1, data1_len) != 1) goto cleanup;
    if (data2_len > 0 && EVP_MAC_update(mctx, data2, data2_len) != 1) goto cleanup;
    
    if (EVP_MAC_final(mctx, out, &out_len, 32) != 1) goto cleanup;
    if (out_len != 32) goto cleanup;

    ok = true;

cleanup:
    EVP_MAC_CTX_free(mctx);
    return ok;
}

bool secure_send(int fd, const std::string& plaintext) {

    const unsigned char* pt = (const unsigned char*)plaintext.data();
    int pt_len = (int)plaintext.size();

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return false;

    // AES-256-CBC encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<unsigned char> ciphertext(pt_len + 16); // CBC padding
    int out1 = 0, out2 = 0;
    bool ok = true;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, PSK_ENC, iv) != 1) ok = false;
    if (ok && pt_len > 0 && EVP_EncryptUpdate(ctx, ciphertext.data(), &out1, pt, pt_len) != 1) ok = false;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + out1, &out2) != 1) ok = false;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    ciphertext.resize(out1 + out2);

    // HMAC(iv || ciphertext) with EVP_MAC (OpenSSL 3.x)
    unsigned char mac[32];
    if (!hmac_sha256_ossl3(PSK_MAC, 32,
                           iv, sizeof(iv),
                           ciphertext.empty() ? nullptr : ciphertext.data(), ciphertext.size(),
                           mac)) {
        return false;
    }

    // payload = IV(16) || CIPHERTEXT || HMAC(32)
    std::vector<unsigned char> payload;
    payload.reserve(16 + ciphertext.size() + 32);
    payload.insert(payload.end(), iv, iv + 16);
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    payload.insert(payload.end(), mac, mac + 32);

    // 你原本的 send_frame(fd, payload)
    return send_frame(fd, payload);
}

bool secure_recv(int fd, std::string& plaintext) {
    plaintext.clear();

    std::vector<unsigned char> payload;
    if (!recv_frame(fd, payload)) return false;

    if (payload.size() < 16 + 32) return false;

    const unsigned char* iv  = payload.data();
    size_t ct_len = payload.size() - 16 - 32;
    const unsigned char* ct  = payload.data() + 16;
    const unsigned char* mac = payload.data() + 16 + ct_len;

    // verify HMAC(iv || ct)
    unsigned char calc[32];
    if (!hmac_sha256_ossl3(PSK_MAC, 32,
                           iv, 16,
                           ct_len == 0 ? nullptr : ct, ct_len,
                           calc)) {
        return false;
    }

    if (CRYPTO_memcmp(calc, mac, 32) != 0) {
        // 被竄改 / key 不一致
        return false;
    }

    // decrypt AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<unsigned char> pt(ct_len + 16);
    int out1 = 0, out2 = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, PSK_ENC, iv) != 1) ok = false;
    if (ok && ct_len > 0 && EVP_DecryptUpdate(ctx, pt.data(), &out1, ct, (int)ct_len) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, pt.data() + out1, &out2) != 1) ok = false;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    pt.resize(out1 + out2);
    plaintext.assign((char*)pt.data(), pt.size());
    return true;
}