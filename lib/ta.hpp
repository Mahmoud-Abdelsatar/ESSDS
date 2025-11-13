#pragma once

#include "ps_crypto.hpp"
#include <relic/relic.h>
#include <string>

namespace ps {

class TA {
public:
    TA();
    ~TA();

    // Initialize TA (generates signing key pair and global params)
    void setup();

    // Sign a certificate payload (id||pubkey||expiry) -> signature bytes
    std::vector<uint8_t> sign_cert(const std::string &id, const std::vector<uint8_t> &pubkey_ser, uint64_t expiry) const;

    // Accessors for public system params
    std::vector<uint8_t> get_psk_serialized() const;
    void export_global_params(ep_t &out_g1, ep2_t &out_g2, gt_t &out_z) const;
    void export_global_params(ps::GlobalParams &out_params) const;
    void export_global_params_to_file(const std::string &filename) const;
private:
    ep_t g1;
    ep2_t g2;
    gt_t z;
    bn_t ssk; // secret signing exponent
    ep_t psk; // public signing key in G1

};

} 