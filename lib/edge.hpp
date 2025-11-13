#pragma once
#include "ps_crypto.hpp"
#include <relic/relic.h>
#include <vector>

namespace ps {


class Edge {
public:
    Edge();
    ~Edge();
    void setSPParams(const ps::SPPublicParams &params); 
    void setSPParams_from_file(const std::string &filename);

    bool accept_reenc_key(const std::vector<uint8_t> &rk_ser, int SN);
    // bool accept_signed_reenc_key(const std::vector<uint8_t> & signed_rk_ser);
    // Re-encrypt c1 (G2 element serialized) -> returns GT element (as serialized bytes)
    std::vector<uint8_t> reencrypt_c1_to_gt(const std::vector<uint8_t> &c1_ser) const;
    //returns re-encrypted CT serialized bytes
    std::vector<uint8_t> receive_reencrypted_ct(const std::vector<uint8_t> &ct_ser);

private:
    ep2_t rk; int LSN;
    ps::SPPublicParams sp_params_;
    ep_t g1_;
    ep2_t g2_;
    gt_t z_;
};

} // namespace ps