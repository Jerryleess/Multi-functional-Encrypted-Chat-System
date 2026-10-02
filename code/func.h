#pragma once
#include <string>
#include <vector>

// ===== PSK =====
//extern const unsigned char PSK_ENC[32];
//extern const unsigned char PSK_MAC[32];

// ===== low-level IO =====
bool send_all(int fd, const void* data, size_t len);
bool recv_all(int fd, void* data, size_t len);

bool send_frame(int fd, const std::vector<unsigned char>& payload);
bool recv_frame(int fd, std::vector<unsigned char>& payload);

// ===== secure channel =====
bool hmac_sha256_ossl3(const unsigned char* key, size_t key_len,
                        const unsigned char* data1, size_t data1_len,
                        const unsigned char* data2, size_t data2_len,
                        unsigned char out[32]);
bool secure_send(int fd, const std::string& plaintext);
bool secure_recv(int fd, std::string& plaintext);