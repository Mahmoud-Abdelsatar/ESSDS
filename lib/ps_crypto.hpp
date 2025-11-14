#pragma once  // or use include guards

#include <relic/relic.h>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>   // for std::runtime_error
#include <cstdint>

namespace ps {


// Initialize and finalize the crypto layer
void init_relic();
void cleanup_relic();

// Serialize helpers for RELIC types
std::vector<uint8_t> serialize_ep(const ep_t &e);
std::vector<uint8_t> serialize_ep2(const ep2_t &e);
std::vector<uint8_t> serialize_gt(const gt_t &e);
std::vector<uint8_t> serialize_bn(const bn_t &b);
void deserialize_ep(ep_t &out, const uint8_t *buf, size_t len);
void deserialize_ep2(ep2_t &out, const uint8_t *buf, size_t len);
void deserialize_gt(gt_t &out, const uint8_t *buf, size_t len);
void deserialize_bn(bn_t &out, const uint8_t *buf, size_t len);
// Symmetric crypto (AES-256-GCM)
struct AesGcmPack { std::vector<uint8_t> ct, iv, tag; };
std::vector<uint8_t> kdf_sha256_to_32(const std::vector<uint8_t>& data);
AesGcmPack aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {});
bool aes_gcm_decrypt(const std::vector<uint8_t>& key, const AesGcmPack &pack, std::vector<uint8_t>& out, const std::vector<uint8_t>& aad = {});

// Symmetric Encryption (AES-256-CBC) - deprecated
std::vector<uint8_t> aes_cbc_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, std::vector<uint8_t>& iv_out);
std::vector<uint8_t> aes_cbc_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);  
// Derive symmetric key from GT element
std::vector<uint8_t> derive_key_from_gt(const gt_t &e);
void export_global_params_to_file(const std::string &filename);

struct GlobalParams {
    ep_t g1;   // example elliptic curve element (G1)
    ep2_t g2;  // example elliptic curve element (G2)
    gt_t z;    // pairing result (GT)
    ep_t psk_ta;
    // Export to file
    void export_to_file(const std::string &filename) const {
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }

        auto write_vector = [&](const std::vector<uint8_t>& data) {
            uint64_t size = data.size();
            out.write(reinterpret_cast<const char*>(&size), sizeof(size));
            out.write(reinterpret_cast<const char*>(data.data()), size);
        };

        std::vector<uint8_t> g1_ser = ps::serialize_ep(g1);
        std::vector<uint8_t> g2_ser = ps::serialize_ep2(g2);
        std::vector<uint8_t> z_ser  = ps::serialize_gt(z);
        std::vector<uint8_t> psk_ser = ps::serialize_ep(psk_ta);
        write_vector(g1_ser);
        write_vector(g2_ser);
        write_vector(z_ser);
        write_vector(psk_ser);

        if (!out.good()) {
            throw std::runtime_error("Error occurred while writing to file: " + filename);
        }

        out.close();
    }

    // Import from file
    void import_from_file(const std::string &filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }

        auto read_vector = [&](std::vector<uint8_t>& data) {
            uint64_t size;
            in.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (!in.good()) throw std::runtime_error("Error reading size from file: " + filename);

            data.resize(size);
            in.read(reinterpret_cast<char*>(data.data()), size);
            if (!in.good()) throw std::runtime_error("Error reading data from file: " + filename);
        };

        std::vector<uint8_t> g1_ser, g2_ser, z_ser, psk_ser;
        read_vector(g1_ser);
        read_vector(g2_ser);
        read_vector(z_ser);
        read_vector(psk_ser);
        ps::deserialize_ep(g1,g1_ser.data(),g1_ser.size());
        ps::deserialize_ep2(g2,g2_ser.data(),g2_ser.size());
        ps::deserialize_gt(z,z_ser.data(),z_ser.size());
        ps::deserialize_ep(psk_ta,psk_ser.data(),psk_ser.size());
        
        if (!in.good() && !in.eof()) {
            throw std::runtime_error("Error occurred while reading from file: " + filename);
        }

        in.close();
    }
};

struct SPPublicParams
{
    ep_t psk1_sp; // g^{ssk_group}
    gt_t psk2_sp; // z^{ssk_group}
    std::vector<uint8_t> export_serialized() const
    {
        auto psk1_ser = ps::serialize_ep(psk1_sp);
        auto psk2_ser = ps::serialize_gt(psk2_sp);
        std::vector<uint8_t> out(psk1_ser);
        out.insert(out.end(),psk2_ser.begin(),psk2_ser.end());
        return out;
    }
    void import_serialized(std::vector<uint8_t> & spparams_ser)
    {
        size_t ep_len=ep_size_bin(psk1_sp,1);
        size_t gt_len=gt_size_bin(psk2_sp,1);
        ep_read_bin(psk1_sp,spparams_ser.data(),ep_len);
        gt_read_bin(psk2_sp,spparams_ser.data()+ep_len,gt_len);
    }

    void export_to_file(const std::string &filename) const {
        auto psk1_ser = ps::serialize_ep(psk1_sp);
        auto psk2_ser = ps::serialize_gt(psk2_sp);
        std::ofstream out(filename, std::ios::binary);
        uint32_t len1 = (uint32_t)psk1_ser.size();
        uint32_t len2 = (uint32_t)psk2_ser.size();
        out.write((char*)&len1, sizeof(len1));
        out.write((char*)psk1_ser.data(), len1);
        out.write((char*)&len2, sizeof(len2));
        out.write((char*)psk2_ser.data(), len2);
        out.close();
    }
    void import_from_file(const std::string &filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in.is_open()) throw std::runtime_error("Cannot open file: " + filename);
        uint32_t len1 = 0, len2 = 0;
        in.read((char*)&len1, sizeof(len1));
        std::vector<uint8_t> psk1_ser(len1);
        in.read((char*)psk1_ser.data(), len1);
        in.read((char*)&len2, sizeof(len2));
        std::vector<uint8_t> psk2_ser(len2);
        in.read((char*)psk2_ser.data(), len2);
        in.close();
        ps::deserialize_ep(psk1_sp, psk1_ser.data(), psk1_ser.size());
        ps::deserialize_gt(psk2_sp, psk2_ser.data(), psk2_ser.size());
    }
};
struct GroupSecretMaterial
{
    bn_t x;
    ep_t w1;
    ep2_t w2;
};
// struct ElGamalSignature {
//     ep_t R;
//     bn_t s;
// };
// bn_t hash_to_bn(const std::vector<uint8_t>& msg);
// ElGamalSignature elgamal_sign(const std::vector<uint8_t>& msg, const bn_t x, const ep_t g);
// bool elgamal_verify(const std::vector<uint8_t>& msg,
//                     const ElGamalSignature& sig,
//                     const ep_t y, const ep_t g);
}