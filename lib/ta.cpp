#include "ta.hpp"
#include <stdexcept>
#include <openssl/sha.h>
namespace ps {

TA::TA() { ep_null(g1);ep2_null(g2);gt_null(z); bn_null(ssk); ep_null(psk); 
    ep_new(g1);ep2_new(g2); gt_new(z); bn_new(ssk); ep_new(psk); }
TA::~TA() { ep_free(g1);ep2_free(g2); gt_free(z); bn_free(ssk); ep_free(psk); }

void TA::setup() {
    bn_t order;
    bn_null(order);
    bn_new(order);

    ep_curve_get_ord(order);  
    // note: ps::init_relic() should already have been called by application
    // generate ssk and psk = g1^{ssk}
    bn_rand_mod(ssk, order);
    ep_mul_basic(psk, g1, ssk);
    // set global params z = e(g1,g2)
    pc_map(z, g1, g2);  
    // export the public system params as well as the public signing key psk as needed
    // You have to serialize g1, g2, z, psk
    bn_free(order);
    // export them to a file
}


std::vector<uint8_t> TA::sign_cert(const std::string &id, const std::vector<uint8_t> &pubkey_ser, uint64_t expiry) const {
    // Simple signature: H(id||pubkey||expiry) raised by ssk -> bn signature
    std::vector<uint8_t> tohash;
    tohash.insert(tohash.end(), id.begin(), id.end());
    tohash.insert(tohash.end(), pubkey_ser.begin(), pubkey_ser.end());
    tohash.push_back((uint8_t)(expiry >> 56)); tohash.push_back((uint8_t)(expiry >> 48));
    tohash.push_back((uint8_t)(expiry >> 40)); tohash.push_back((uint8_t)(expiry >> 32));
    tohash.push_back((uint8_t)(expiry >> 24)); tohash.push_back((uint8_t)(expiry >> 16));
    tohash.push_back((uint8_t)(expiry >> 8)); tohash.push_back((uint8_t)(expiry >> 0));

    uint8_t digest[32];
    SHA256(tohash.data(), tohash.size(), digest);

    bn_t h; bn_null(h); bn_new(h);
    bn_read_bin(h, digest, 32);

    // sig = h^{ssk} in G1? or bn-style. For portability return bn serialized sig
    bn_t sig; bn_null(sig); bn_new(sig);
    bn_mul(sig, h, ssk);

    int len = bn_size_bin(sig);
    std::vector<uint8_t> out(len);
    bn_write_bin(out.data(), len, sig);

    bn_free(h); bn_free(sig);
    return out;
}

std::vector<uint8_t> TA::get_psk_serialized() const { return ps::serialize_ep(psk); }
void TA::export_global_params(ep_t &out_g1, ep2_t &out_g2, gt_t &out_z) const {
    ep_copy(out_g1, g1);
    ep2_copy(out_g2, g2);
    gt_copy(out_z, z);
}
void TA::export_global_params(ps::GlobalParams &out_params) const {
    ep_copy(out_params.g1, g1);
    ep2_copy(out_params.g2, g2);
    gt_copy(out_params.z, z);
    ep_copy(out_params.psk_ta, psk);
}
void TA::export_global_params_to_file(const std::string &filename) const {
    ps::GlobalParams gp;
    ep_copy(gp.g1, g1);
    ep2_copy(gp.g2, g2);
    gt_copy(gp.z, z);
    ep_copy(gp.psk_ta, psk);
    gp.export_to_file(filename);
}

} // namespace ps