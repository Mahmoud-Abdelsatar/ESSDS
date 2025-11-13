#pragma once

#include "ps_crypto.hpp"
#include <relic/relic.h>
#include <vector>
#include <string>

namespace ps {

class SP {
public:
    SP(const std::string &id);
    ~SP();

    // initialize sp keys and group material
    void init_keys();
    void set_global_params(const ps::GlobalParams &params);
    void set_global_params_from_file(const std::string &filename);

    // assign group material for vehicle
    ps::GroupSecretMaterial generate_group_material_for_vehicle() const;
    // assign group material for vehicle and serialize
    
    std::vector<uint8_t> generate_group_material_serialized_for_vehicle() const;

    // service: generate re-encryption key (returns serialized ep2)
    std::vector<uint8_t> generate_reenc_key() const;
    // std::vector<uint8_t> generate_sign_reenc_key(uint64_t SN);
    // signcrypt data -> returns serialized CT components (application-level struct later)
    // (we will later replace this with a canonical struct); for now returns a simple vector
    std::vector<uint8_t> signcrypt(const std::vector<uint8_t> &m, uint64_t SN);

    // getters
    std::vector<uint8_t> get_psk1_serialized() const; // serialized psk1_sp
    std::vector<uint8_t> get_pk1_serialized() const;  // serialized pk1 (encryption public key in G2)
    void export_psk1_psk2(ep_t &out_psk1, gt_t &out_psk2) const; 
    void export_spparams(ps::SPPublicParams &out_params) const;
private:
    std::string id;
    // encryption key
    bn_t sk1; ep_t pk1;
    // signing key
    bn_t ssk_sp; ep_t psk1_sp; gt_t psk2_sp;
    // group material
    bn_t sk; ep_t h; ep2_t A; ep2_t gpk; // gpk in G2
    // global params would be loaded from file or passed in
    ps::GlobalParams gp_params_;
    ep_t g1_;
    ep2_t g2_;
    gt_t z_;
};

} // namespace ps