#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace std;
using namespace std::chrono;
// Compile with: g++ openssl-benchmark.cpp -o openssl-bench -lssl -lcrypto

template <typename F>
pair<double, double> benchmark_stats(F func, int inner_loop = 1000, int outer_loop = 1) {
    vector<double> times;
    times.reserve(outer_loop);

    for (int i = 0; i < outer_loop; ++i) {
        auto start = high_resolution_clock::now();
        for (int j = 0; j < inner_loop; ++j) func();
        auto end = high_resolution_clock::now();
        double total = duration_cast<nanoseconds>(end - start).count();
        times.push_back(total / inner_loop);
    }

    double sum = 0.0;
    for (double t : times) sum += t;
    double mean = sum / outer_loop;

    double sq_sum = 0.0;
    for (double t : times) sq_sum += (t - mean) * (t - mean);
    double stddev = sqrt(sq_sum / outer_loop);

    return {mean, stddev};
}


int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    cout << "🔐 Cryptographic Benchmark Suite (OpenSSL)\n";
    cout << "-------------------------------------------\n";

    // SHA256
    unsigned char input[32] = "Benchmark message for hashing!";
    unsigned char hash_out[SHA256_DIGEST_LENGTH];
    auto [sha_avg, sha_std] = benchmark_stats([&]() {
        SHA256(input, sizeof(input), hash_out);
    });
    cout << "SHA256 Hash:         " << sha_avg << " ns (±" << sha_std << ")\n";

    // HMAC-SHA256
    unsigned char hkey[] = "secret-key";
    unsigned char hdata[] = "message";
    unsigned char hmac_out[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    auto [hmac_avg, hmac_std] = benchmark_stats([&]() {
        HMAC(EVP_sha256(), hkey, strlen((char *)hkey), hdata, strlen((char *)hdata), hmac_out, &hmac_len);
    });
    cout << "HMAC-SHA256:         " << hmac_avg << " ns (±" << hmac_std << ")\n";

    // AES-CBC Encryption
    auto [aes_avg, aes_std] = benchmark_stats([]() {
        unsigned char key[17] = "0123456789abcdef";
        unsigned char iv[17] = "fedcba9876543210";
        unsigned char pt[17] = "plaintext1234567";
        unsigned char ct[17];
        AES_KEY aes;
        AES_set_encrypt_key(key, 128, &aes);
        AES_cbc_encrypt(pt, ct, sizeof(pt), &aes, iv, AES_ENCRYPT);
    });
    cout << "AES-CBC Encryption:  " << aes_avg << " ns (±" << aes_std << ")\n";

    // HKDF (simplified)
    auto [hkdf_avg, hkdf_std] = benchmark_stats([]() {
        unsigned char ikm[33] = "ikm: input key material.......";
        unsigned char salt[17] = "salt...........";
        unsigned char prk[33], okm[33];
        unsigned int len;
        HMAC(EVP_sha256(), salt, sizeof(salt), ikm, sizeof(ikm), prk, &len);
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk, len, EVP_sha256(), NULL);
        unsigned char info[] = "info";
        unsigned char c = 1;
        HMAC_Update(ctx, info, sizeof(info));
        HMAC_Update(ctx, &c, 1);
        HMAC_Final(ctx, okm, &len);
        HMAC_CTX_free(ctx);
    });
    cout << "HKDF-SHA256:         " << hkdf_avg << " ns (±" << hkdf_std << ")\n";

    // Modular Exponentiation
    auto [modexp_avg, modexp_std] = benchmark_stats([]() {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *a = BN_new(), *b = BN_new(), *m = BN_new(), *r = BN_new();
        BN_set_word(a, 123456);
        BN_set_word(b, 654321);
        BN_set_word(m, 0xFFFFFFFB);
        BN_mod_exp(r, a, b, m, ctx);
        BN_free(a); BN_free(b); BN_free(m); BN_free(r); BN_CTX_free(ctx);
    });
    cout << "Modular Exp:         " << modexp_avg << " ns (±" << modexp_std << ")\n";

    // Modular Inverse
    auto [modinv_avg, modinv_std] = benchmark_stats([]() {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *a = BN_new(), *m = BN_new(), *r = BN_new();
        BN_set_word(a, 1234567);
        BN_set_word(m, 0xFFFFFFFB);
        BN_mod_inverse(r, a, m, ctx);
        BN_free(a); BN_free(m); BN_free(r); BN_CTX_free(ctx);
    });
    cout << "Modular Inverse:     " << modinv_avg << " ns (±" << modinv_std << ")\n";

    // EC Scalar Mult & Point Addition
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *G = EC_GROUP_get0_generator(group);

    auto [ec_mult_avg, ec_mult_std] = benchmark_stats([&]() {
        BIGNUM *k = BN_new();
        BN_rand(k, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        EC_POINT *R = EC_POINT_new(group);
        EC_POINT_mul(group, R, NULL, G, k, NULL);
        EC_POINT_free(R);
        BN_free(k);
    });
    cout << "EC Scalar Mult:      " << ec_mult_avg << " ns (±" << ec_mult_std << ")\n";

    EC_POINT *P = EC_POINT_new(group), *Q = EC_POINT_new(group);
    BIGNUM *k1 = BN_new(), *k2 = BN_new();
    BN_rand(k1, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_rand(k2, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    EC_POINT_mul(group, P, NULL, G, k1, NULL);
    EC_POINT_mul(group, Q, NULL, G, k2, NULL);

    auto [ec_add_avg, ec_add_std] = benchmark_stats([&]() {
        EC_POINT *R = EC_POINT_new(group);
        EC_POINT_add(group, R, P, Q, NULL);
        EC_POINT_free(R);
    });
    cout << "EC Point Addition:   " << ec_add_avg << " ns (±" << ec_add_std << ")\n";

    EC_POINT_free(P); EC_POINT_free(Q); BN_free(k1); BN_free(k2);
    EC_GROUP_free(group);

    // ECDSA Sign/Verify
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    // Prepare dummy signature
    size_t siglen = 0;
    unsigned char msg[32];
    RAND_bytes(msg, sizeof(msg));
    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    EVP_DigestSignInit(tmp, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(tmp, NULL, &siglen, msg, sizeof(msg));
    EVP_MD_CTX_free(tmp);
    unsigned char *sigbuf = new unsigned char[siglen];

    auto [sign_avg, sign_std] = benchmark_stats([&]() {
        unsigned char m[32];
        RAND_bytes(m, sizeof(m));
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        size_t len = siglen;
        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSign(ctx, sigbuf, &len, m, sizeof(m));
        EVP_MD_CTX_free(ctx);
    });

    // Prepare valid signature for verify benchmark
    RAND_bytes(msg, sizeof(msg));
    EVP_MD_CTX *sigctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(sigctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(sigctx, sigbuf, &siglen, msg, sizeof(msg));
    EVP_MD_CTX_free(sigctx);

    auto [verify_avg, verify_std] = benchmark_stats([&]() {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerify(ctx, sigbuf, siglen, msg, sizeof(msg));
        EVP_MD_CTX_free(ctx);
    });

    cout << "ECDSA Sign:          " << sign_avg << " ns (±" << sign_std << ")\n";
    cout << "ECDSA Verify:        " << verify_avg << " ns (±" << verify_std << ")\n";

    // Cleanup
    delete[] sigbuf;
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
