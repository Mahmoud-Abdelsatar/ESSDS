#pragma once

#include "ps_crypto.hpp"
#include <relic/relic.h>
#include <vector>
#include <string>

namespace ps {

class Vehicle {
public:
    Vehicle(const std::string &id);
    ~Vehicle();
    void setSPParams(const ps::SPPublicParams &params);
    void setSPParams_from_file(const std::string &filename);
    void setGlobalParams(const ps::GlobalParams &params);
    void setGlobalParams_from_file(const std::string &filename); 
    // Receive and store its group secrets (x_i, w1, w2)
    void receive_group_material(const bn_t &x_i, const ep_t &w1, const ep2_t &w2);
    void recieve_group_secret_material(const ps::GroupSecretMaterial &gsm);
    void receive_group_secret_material_serialized(const std::vector<uint8_t>& gsm_ser);
    // Unsigncrypt: given GT re-encrypted c1' and AES pack, try to recover message
    bool unsigncrypt(const gt_t &c1prime, const std::vector<uint8_t> &c2_ct, const std::vector<uint8_t>& c2_iv, const std::vector<uint8_t>& c2_tag, const bn_t &SN, const bn_t &t1, const bn_t &s, const ep_t &psk1_sp, const gt_t &psk2_sp);
    bool unsigncrypt(const std::vector<uint8_t>& ct_ser);
    bool unsigncrypt(const std::vector<uint8_t>& reenc_ct_ser, std::vector<uint8_t>& out_message);
private:
    std::string id;
    bn_t x_i;
    ep_t w1; ep2_t w2;
    std::vector<uint8_t> gsk_sym; // derived symmetric key for group
    ps::SPPublicParams sp_params_;
    ps::GlobalParams gp_params_;
    ep_t g1_;
    ep2_t g2_;
    gt_t z_;
};

} // namespace ps