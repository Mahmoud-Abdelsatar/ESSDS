#include "ps_crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>

namespace ps {

void init_relic() {
    if (core_init() != RLC_OK) throw std::runtime_error("RELIC core_init failed");
    if (pc_param_set_any() != RLC_OK) throw std::runtime_error("RELIC pairings not available");
}

void cleanup_relic() { core_clean(); }

std::vector<uint8_t> serialize_ep(const ep_t &e) {
    int n = ep_size_bin(e, 1);
    std::vector<uint8_t> out(n);
    ep_write_bin(out.data(), n, e, 1);
    return out;
}
std::vector<uint8_t> serialize_ep2(const ep2_t &e) {
    int n = ep2_size_bin(e, 1);
    std::vector<uint8_t> out(n);
    ep2_write_bin(out.data(), n, e, 1);
    return out;
}
std::vector<uint8_t> serialize_gt(const gt_t &e) {
    int n = gt_size_bin(e, 1);
    std::vector<uint8_t> out(n);
    gt_write_bin(out.data(), n, e, 1);
    return out;
}

std::vector<uint8_t> serialize_bn(const bn_t &b) {
    int n = bn_size_bin(b);
    std::vector<uint8_t> out(n);
    bn_write_bin(out.data(), n, b);
    return out;
}

void deserialize_ep(ep_t &out, const uint8_t *buf, size_t len) {
    ep_read_bin(out, buf, len);
}
void deserialize_ep2(ep2_t &out, const uint8_t *buf, size_t len) {
    ep2_read_bin(out, buf, len);
}
void deserialize_gt(gt_t &out, const uint8_t *buf, size_t len) {
    gt_read_bin(out, buf, len);
}

void deserialize_bn(bn_t &out, const uint8_t *buf, size_t len) {
    bn_read_bin(out, buf, len);
}
std::vector<uint8_t> kdf_sha256_to_32(const std::vector<uint8_t>& data) {
    uint8_t out[32];
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, data.data(), data.size());
    EVP_DigestFinal_ex(md, out, nullptr);
    EVP_MD_CTX_free(md);
    return std::vector<uint8_t>(out, out+32);
}

AesGcmPack aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad) {
    AesGcmPack pack;
    pack.iv.resize(12);
    if (RAND_bytes(pack.iv.data(), (int)pack.iv.size()) != 1) throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) throw std::runtime_error("EVP_EncryptInit_ex failed");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)pack.iv.size(), nullptr)) throw std::runtime_error("EVP_CIPHER_CTX_ctrl ivlen failed");
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), pack.iv.data())) throw std::runtime_error("EVP_EncryptInit_ex key/iv failed");

    int len = 0;
    if (!aad.empty()) EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());

    pack.ct.resize(plaintext.size());
    if (1 != EVP_EncryptUpdate(ctx, pack.ct.data(), &len, plaintext.data(), (int)plaintext.size())) throw std::runtime_error("EVP_EncryptUpdate failed");
    int ctlen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, pack.ct.data()+len, &len)) throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ctlen += len; pack.ct.resize(ctlen);

    pack.tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)pack.tag.size(), pack.tag.data())) throw std::runtime_error("GCM get tag failed");
    EVP_CIPHER_CTX_free(ctx);
    return pack;
}

bool aes_gcm_decrypt(const std::vector<uint8_t>& key, const AesGcmPack &pack, std::vector<uint8_t>& out, const std::vector<uint8_t>& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)pack.iv.size(), nullptr)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), pack.iv.data())) { EVP_CIPHER_CTX_free(ctx); return false; }
    int len = 0;
    if (!aad.empty()) EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());

    out.resize(pack.ct.size());
    if (1 != EVP_DecryptUpdate(ctx, out.data(), &len, pack.ct.data(), (int)pack.ct.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
    int outlen = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)pack.tag.size(), (void*)pack.tag.data())) { EVP_CIPHER_CTX_free(ctx); return false; }
    int ret = EVP_DecryptFinal_ex(ctx, out.data()+len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) return false;
    outlen += len; out.resize(outlen);
    return true;
}
std::vector<uint8_t> aes_cbc_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, std::vector<uint8_t>& iv_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    iv_out.resize(16);
    RAND_bytes(iv_out.data(), (int)iv_out.size());

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv_out.data()) != 1)
        throw std::runtime_error("EncryptInit failed");

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
        throw std::runtime_error("EncryptUpdate failed");

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("EncryptFinal failed");

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}
std::vector<uint8_t> aes_cbc_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("DecryptInit failed");

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        throw std::runtime_error("DecryptUpdate failed");

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        throw std::runtime_error("DecryptFinal failed");

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
std::vector<uint8_t> derive_key_from_gt(const gt_t &e) {
    int n = gt_size_bin(e, 1);
    std::vector<uint8_t> buf(n);
    gt_write_bin(buf.data(), n, e, 1);
    return kdf_sha256_to_32(buf);
}



// Hash to scalar (bn_t)
// bn_t hash_to_bn(const std::vector<uint8_t>& msg) {
//     uint8_t hash[SHA256_DIGEST_LENGTH];
//     SHA256(msg.data(), msg.size(), hash);
//     bn_t h; bn_null(h); bn_new(h);
//     bn_read_bin(h, hash, SHA256_DIGEST_LENGTH);
//     bn_mod(h, h, ep_curve_get_ord());
//     return h;
// }

// Sign function
// ElGamalSignature elgamal_sign(const std::vector<uint8_t>& msg, const bn_t x, const ep_t g) {
//     ElGamalSignature sig;
//     ep_null(sig.R); bn_null(sig.s);
//     ep_new(sig.R); bn_new(sig.s);

//     bn_t k, k_inv, h, r_x, tmp;
//     bn_null(k); bn_null(k_inv); bn_null(h); bn_null(r_x); bn_null(tmp);
//     bn_new(k); bn_new(k_inv); bn_new(h); bn_new(r_x); bn_new(tmp);

//     const bn_t order;
//     bn_null(order); bn_new(order); 
//     ep_curve_get_ord(order);

//     // Random nonce
//     bn_rand_mod(k, order);

//     // Compute R = g^k
//     ep_mul_gen(sig.R, k);

//     // Hash message
//     std::vector<uint8_t> hbytes =ps::kdf_sha256_to_32(msg);
//     bn_copy(h, hbytes.data(),32);

//     // Convert R -> scalar (hash)
//     uint8_t buf[64];
//     int len = ep_size_bin(sig.R, 1);
//     ep_write_bin(buf, len, sig.R, 1);
//     uint8_t hashR[32];
//     SHA256(buf, len, hashR);
//     bn_read_bin(r_x, hashR, 32);
//     bn_mod(r_x, r_x, order);

//     // s = k^-1 * (h - x*r_x) mod order
//     bn_mod_inv(k_inv, k, order);
//     bn_mul(tmp, x, r_x);
//     bn_mod(tmp, tmp, order);
//     bn_sub(tmp, h, tmp);
//     bn_mod(tmp, tmp, order);
//     bn_mul(sig.s, tmp, k_inv);
//     bn_mod(sig.s, sig.s, order);

//     // Cleanup
//     bn_free(k); bn_free(k_inv); bn_free(h); bn_free(r_x); bn_free(tmp);

//     return sig;
// }

// // Verify function
// bool elgamal_verify(const std::vector<uint8_t>& msg,
//                     const ElGamalSignature& sig,
//                     const ep_t y, const ep_t g) {
//     bn_t h, r_x;
//     ep_t left, right, r1, r2;
//     bn_null(h); bn_null(r_x);
//     ep_null(left); ep_null(right); ep_null(r1); ep_null(r2);
//     bn_new(h); bn_new(r_x);
//     ep_new(left); ep_new(right); ep_new(r1); ep_new(r2);

//     const bn_t order = ep_curve_get_ord();

//     h = hash_to_bn(msg);

//     // Convert R -> r_x
//     uint8_t buf[64];
//     int len = ep_size_bin(sig.R, 1);
//     ep_write_bin(buf, len, sig.R, 1);
//     uint8_t hashR[SHA256_DIGEST_LENGTH];
//     SHA256(buf, len, hashR);
//     bn_read_bin(r_x, hashR, SHA256_DIGEST_LENGTH);
//     bn_mod(r_x, r_x, order);

//     // left = g^h
//     ep_mul_gen(left, h);

//     // right = y^{r_x} * R^{s}
//     ep_mul(r1, y, r_x);
//     ep_mul(r2, sig.R, sig.s);
//     ep_add(right, r1, r2);
//     ep_norm(right, right);

//     bool ok = ep_cmp(left, right) == CMP_EQ;

//     // Cleanup
//     bn_free(h); bn_free(r_x);
//     ep_free(left); ep_free(right); ep_free(r1); ep_free(r2);

//     return ok;
// }

}