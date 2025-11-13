#include "sp.hpp"
#include <stdexcept>
#include <iostream>
namespace ps {

SP::SP(const std::string &id): id(id) {
    bn_null(sk1); bn_new(sk1); ep2_null(pk1); ep2_new(pk1);
    bn_null(ssk_sp); bn_new(ssk_sp); ep_null(psk1_sp); ep_new(psk1_sp); gt_null(psk2_sp); gt_new(psk2_sp);
    bn_null(sk); bn_new(sk); ep_null(h); ep_new(h); ep2_null(A); ep2_new(A); ep2_null(gpk); ep2_new(gpk);
    ep_null(g1_);ep_new(g1_);ep_curve_get_gen(g1_);
    ep2_null(g2_);ep2_new(g2_); ep2_curve_get_gen(g2_);
    gt_null(z_); gt_new(z_);
    pc_map(z_,g1_,g2_);
}
SP::~SP() {
    // free items; omitted for brevity
}

void SP::init_keys() {
    //load global params g1, g2, z from file or assume initialized
    // ps::GlobalParams gp;
    // // --- load from file or assume already loaded ---
    // gp.export_to_file("global_params.dat"); // placeholder
    // encryption key
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);
    ep_t g1; ep_null(g1); ep_new(g1); ep_curve_get_gen(g1);
    ep2_t g2; ep2_null(g2); ep2_new(g2); ep2_curve_get_gen(g2);
    
    bn_rand_mod(sk1, order);
    ep_mul_basic(pk1, g1, sk1);
    ep2_free(g2);
    // signing key
    bn_rand_mod(ssk_sp, order);
    ep_mul_basic(psk1_sp, g1, ssk_sp);
    // psk2_sp = e(g1,g2)^{ssk_sp}
    gt_t z; gt_null(z); gt_new(z);
    pc_map(z, g1, g2);
    gt_exp(psk2_sp, z, ssk_sp);
    ep_free(g1); gt_free(z);

    // group material
    bn_rand_mod(sk, order);
    ep_rand(h); ep2_rand(A);
    // compute gpk as g2^{H(e(h,A))}
    gt_t eHA; gt_null(eHA); gt_new(eHA);
    pc_map(eHA, h, A);
    auto key = derive_key_from_gt(eHA);
    //cout key value in hex for debug
    
    std::string hex;
    for (auto b : key) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout<< "SP: derived gsk key = " << hex << std::endl;               

    bn_t gsk; bn_null(gsk); bn_new(gsk);
    bn_read_bin(gsk, key.data(), (int)key.size());
    // ep2_t g2gen; ep2_null(g2gen); ep2_new(g2gen); ep2_curve_get_gen(g2gen);
    ep2_mul_basic(gpk, g2, gsk);
    ep2_free(g2); gt_free(eHA); bn_free(gsk);
    bn_free(order);
}
void SP::set_global_params(const ps::GlobalParams &params) { gp_params_ = params; }
void SP::set_global_params_from_file(const std::string &filename) {
    gp_params_.import_from_file(filename);
}

GroupSecretMaterial SP::generate_group_material_for_vehicle() const {
    GroupSecretMaterial gsm;
    bn_null(gsm.x); bn_new(gsm.x);
    ep_null(gsm.w1); ep_new(gsm.w1);
    ep2_null(gsm.w2); ep2_new(gsm.w2);
     bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);
    // generate random x
    bn_rand_mod(gsm.x, order);
    // w1 = h^{x + sk}
    bn_t x_plus_sk; bn_null(x_plus_sk); bn_new(x_plus_sk);
    bn_add(x_plus_sk, gsm.x, sk);
    ep_mul_basic(gsm.w1, h, x_plus_sk);
    // w2 = A^{1/(x + sk)}
    bn_t inv; bn_null(inv); bn_new(inv);
    bn_mod_inv(inv, x_plus_sk,order);
    ep2_mul_basic(gsm.w2, A, inv);
    bn_free(x_plus_sk); bn_free(inv)
    bn_free(order);
    return gsm;
}

std::vector<uint8_t> SP::generate_group_material_serialized_for_vehicle() const {
    GroupSecretMaterial gsm = generate_group_material_for_vehicle();
    auto x_ser = ps::serialize_bn(gsm.x);
    auto w1_ser = ps::serialize_ep(gsm.w1);
    auto w2_ser = ps::serialize_ep2(gsm.w2);
    // cout w2_ser size for debug
    std::cout << "SP: serialized w2 size = " << w2_ser.size() << " bytes." << std::endl;    
    std::vector<uint8_t> out;
    // concatenate all serialized parts
    out.insert(out.end(), x_ser.begin(), x_ser.end());
    out.insert(out.end(), w1_ser.begin(), w1_ser.end());
    out.insert(out.end(), w2_ser.begin(), w2_ser.end());
    // free
    bn_free(gsm.x); ep_free(gsm.w1); ep2_free(gsm.w2);
    return out;
}

// } // namespace ps
std::vector<uint8_t> SP::generate_reenc_key() const {
    // rk = gpk^{1/sk1} in G2
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);
    bn_t inv; bn_null(inv); bn_new(inv);
    bn_mod_inv(inv, sk1, order);
    ep2_t rk; ep2_null(rk); ep2_new(rk);
    ep2_mul_basic(rk, gpk, inv);
    auto out = ps::serialize_ep2(rk);
    // cout the out value in hex for debug
    std::string hex; 
    for (auto b : out) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "SP: reenc key = " << hex << std::endl;
    ep2_free(rk); bn_free(inv);
    bn_free(order);
    return out;
}
// std::vector<uint8_t> SP::generate_sign_reenc_key(uint64_t SN) const
// {
//     std::vector<uint8_t> rk=generate_reenc_key();
//     // sign rk||SN using the ssk_{sp}
//     // 2. Prepare message = rk || SN
//     std::vector<uint8_t> msg(rk);
//     uint8_t sn_bytes[sizeof(SN)];
//     memcpy(sn_bytes, &SN, sizeof(SN));
//     msg.insert(msg.end(), sn_bytes, sn_bytes + sizeof(SN));

//     // 3. Sign using ElGamal on G1
//     ps::ElGamalSignature sig = ps::elgamal_sign(msg, ssk_sp, g1_); // gp_.g1 is generator

//     // serialize rk, SN, and signature as output

//     std::vector<uint8_t> R_ser=ps::serialize_ep(sig.R);
//     std::vector<uint8_t> s_ser=ps::serialize_bn(sig.s);
//     msg.insert(msg.end(),R_ser.begin(),R_ser.end());
//     msg.insert(msg.end(),s_ser.begin(),s_ser.end());
//     return msg;
// }
std::vector<uint8_t> SP::signcrypt(const std::vector<uint8_t> &m, uint64_t SN) {
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);
    //pick random x1 and x2 in bn_t
    bn_t x1, x2; bn_null(x1); bn_new(x1); bn_null(x2); bn_new(x2);
    bn_rand_mod(x1, order);
    bn_rand_mod(x2, order);
    bn_t r; bn_null(r); bn_new(r);
    bn_add(r, x1, x2); bn_mod(r, r, order);
    // set R=g^r
    ep_t R; ep_null(R); ep_new(R);
    ep_t g; ep_null(g); ep_new(g); ep_curve_get_gen(g);
    ep2_t g2; ep2_null(g2); ep2_new(g2); ep2_curve_get_gen(g2);
    ep_mul_basic(R, g, r);
    // compute z^{x1}
    gt_t z_x1; gt_null(z_x1); gt_new(z_x1);
    // pc_map(z_x1, gp_params_.g1, gp_params_.g2);
    //cout the gp_params_ values in hex for debug
    std::string hex_g1, hex_g2;
    int g1len = ep_size_bin(gp_params_.g1, 1);
    std::vector<uint8_t> g1buf(g1len);
    ep_write_bin(g1buf.data(), g1len, gp_params_.g1, 1);
    for (auto b : g1buf) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex_g1 += buf;
    }
    int g2len = ep2_size_bin(gp_params_.g2, 1);
    std::vector<uint8_t> g2buf(g2len);
    ep2_write_bin(g2buf.data(), g2len, gp_params_.g2, 1);
    for (auto b : g2buf) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex_g2 += buf;
    }
    std::cout << "SP: gp_params_.g1 = " << hex_g1 << std::endl;
    std::cout << "SP: gp_params_.g2 = " << hex_g2 << std::endl;
    pc_map(z_x1, g, g2); 
    gt_exp(z_x1, z_x1, x1);
    // cout the z^{x1} value in hex for debug
    std::string hex;
    int zlen = gt_size_bin(z_x1, 1);
    std::vector<uint8_t> zbuf(zlen);
    gt_write_bin(zbuf.data(), zlen, z_x1, 1);
    for (auto b : zbuf) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "SP: z^{x1} = " << hex << std::endl;
    // compute z^{x2}
    gt_t z_x2; gt_null(z_x2); gt_new(z_x2);
    pc_map(z_x2, g, g2);
    gt_exp(z_x2, z_x2, x2); 
    // compute c1=pk1^{x1} in G1
    ep_t c1; ep_new(c1); ep_mul(c1, pk1, x1);
    auto c1_ser = ps::serialize_ep(c1);
    // compute c2 = AES-GCM encrypt of m under key derived from z^{x1} 
    auto k_sym = derive_key_from_gt(z_x1);
    // cout the k_sym value in hex for debug
    std::string hex2;
    for (auto b : k_sym) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex2 += buf;
    }
    std::cout << "SP: derived sym key = " << hex2 << std::endl;
    // set mp=m||z^{x2} as bytes
    std::vector<uint8_t> mp(m);
    // int zlen = gt_size_bin(z_x2, 1);
    std::vector<uint8_t> z2buf(zlen);
    gt_write_bin(z2buf.data(), zlen, z_x2, 1);
    mp.insert(mp.end(), z2buf.begin(), z2buf.end());
    // AES-GCM encrypt mp under gsk_sym                                                                                     
    //auto c2_ct = cu.aesEncrypt(mp, gsk_sym);
    // use ps::aes_cbd_encrypt for legacy compatibility
    std::vector<uint8_t> iv;
    auto c2_ct = ps::aes_cbc_encrypt(mp, k_sym, iv);  
     // cout the iv value in hex for debug
    std::string iv_hex;
    for (auto b : iv) {                
        char buf[3];
        sprintf(buf, "%02x", b);
        iv_hex += buf;
    }
    std::cout << "SP: AES iv = " << iv_hex << std::endl;
    // compute t0=H(m)
    // std::string t0hex = cu.sha256(std::string(m.begin(), m.end()));
    // compute t0=H(m) using ps::kdf_sha256_to_32 for legacy compatibility
    // CryptoUtils cu;
    auto t0hash_bytes = ps::kdf_sha256_to_32(m);
    // std::string t0hex;
    // for (auto b : t0hash_bytes) {
    //     char buf[3];
    //     sprintf(buf, "%02x", b);
    //     t0hex += buf;
    // }       
    //compute t1=H(c1) using ps::kdf_sha256_to_32 for legacy compatibility
    auto t1hash_bytes = ps::kdf_sha256_to_32(c1_ser);
    //compute t2=H(t0||t1||c2||SN) using ps::kdf_sha256_to_32 for legacy compatibility
    std::vector<uint8_t> t2in;
    // append t0 bytes
    // for (size_t i=0; i<t0hash_bytes.size(); ++i) 
    //     t2in.push_back(t0hash_bytes[i]);
    t2in.insert(t2in.end(), t0hash_bytes.begin(), t0hash_bytes.end());
    // append t1 bytes
    // for (size_t i=0; i<t1hash_bytes.size(); ++i) 
    //     t2in.push_back(t1hash_bytes[i]);
    t2in.insert(t2in.end(), t1hash_bytes.begin(), t1hash_bytes.end());
    // append c2 bytes
    t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) 
        t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    auto t2hash_bytes = ps::kdf_sha256_to_32(t2in);
    // cout t2hash_bytes in hex for debug
    std::string t2hex;
    for (auto b : t2hash_bytes) {
        char buf[3];
        sprintf(buf, "%02x", b);
        t2hex += buf;
    }
    std::cout << "SP: t2 = " << t2hex << std::endl;
    // convert t2hex to bn
    bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    bn_read_bin(t2bn, t2hash_bytes.data(), (int)t2hash_bytes.size());
    bn_mod(t2bn, t2bn, order);
    // compute s = 1/(t2*r + ssk_sp) mod order
    // std::string c1str((char*)c1_ser.data(), c1_ser.size());
    // std::string t1hex = cu.sha256(c1str);
    // compute t2=H(t0||t1||c2||SN)
    // std::vector<uint8_t> t2in;
    // append t0 bytes
    // for (size_t i=0; i<t0hex.size(); ++i) t2in.push_back((uint8_t)t0hex[i]);
    // append t1 bytes
    // for (size_t i=0; i<t1hex.size(); ++i) t2in.push_back((uint8_t)t1hex[i]);
    // append c2 bytes
    // t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // append SN as 8 bytes BE
    // for (int i=7; i>=0; --i) t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    // std::string t2hex = cu.sha256(std::string((char*)t2in.data(), t2in.size()));
    // convert t2hex to bn
    // bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    // std::vector<uint8_t> t2bytes;
    // for (size_t i=0; i<t2hex.size(); i+=2) {
    //     t2bytes.push_back((uint8_t)strtol(t2hex.substr(i,2).c_str(), nullptr, 16));
    // }
    // bn_read_bin(t2bn, t2bytes.data(), (int)t2bytes.size());
    // bn_mod(t2bn, t2bn, order);
    // compute s = 1/(t2*r + ssk_sp) mod order
    bn_t tmp; bn_null(tmp); bn_new(tmp); bn_mul(tmp, t2bn, r); bn_add(tmp, tmp, ssk_sp); bn_mod(tmp, tmp, order);
    bn_t s; bn_null(s); bn_new(s);
    bn_mod_inv(s, tmp, order);
    // serialize R, s, c1, c2_ct as output
    auto R_ser = ps::serialize_ep(R);
    auto s_ser = ps::serialize_bn(s);
    // concatenate all parts: [iv][t0hex][ R_ser][s_ser][SN][c1_ser][c2_ct]
    std::vector<uint8_t> out;
    // append iv bytes
    out.insert(out.end(), iv.begin(), iv.end());
    // append t0hex as bytes
    // for (size_t i=0; i<t0hhash_bytes.size(); ++i) 
    //     out.push_back(t0hex[i]);
    out.insert(out.end(), t0hash_bytes.begin(), t0hash_bytes.end());
    out.insert(out.end(), R_ser.begin(), R_ser.end());
    out.insert(out.end(), s_ser.begin(), s_ser.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) 
        out.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    out.insert(out.end(), c1_ser.begin(), c1_ser.end());
    out.insert(out.end(), c2_ct.begin(), c2_ct.end());
    std::cout<<"IV size: " << iv.size() << ", t0hash size: " << t0hash_bytes.size() 
             << ", R size: " << R_ser.size() << ", s size: " << s_ser.size() 
             << ", c1 size: " << c1_ser.size() << ", c2 size: " << c2_ct.size() << std::endl;
    // free
    bn_free(order); bn_free(x1); bn_free(x2); bn_free(r);
    ep_free(R); ep_free(g); gt_free(z_x1); gt_free(z_x2);
    ep_free(c1); bn_free(t2bn); bn_free(tmp); bn_free(s);
    return out;
}


    // // concatenate all parts: [ R_ser][s_ser][c1_ser][c2_ct]
    // std::vector<uint8_t> out;
    // out.insert(out.end(), R_ser.begin(), R_ser.end());
    // out.insert(out.end(), s_ser.begin(), s_ser.end());
    // out.insert(out.end(), c1_ser.begin(), c1_ser.end());
    // out.insert(out.end(), c2_ct.begin(), c2_ct.end());
    // // free
    // bn_free(order); bn_free(x1); bn_free(x2); bn_free(r);
    // ep_free(R); ep_free(g); gt_free(z_x1); gt_free(z_x2);
    // ep_free(c1); bn_free(t2bn); bn_free(tmp); bn_free(s);
    // return out;

    
    // placeholder: full implementation will follow in next step
    // std::vector<uint8_t> buf(m);
    // buf.push_back((uint8_t)(SN & 0xFF));
    // return buf;
// }

std::vector<uint8_t> SP::get_psk1_serialized() const { return ps::serialize_ep(psk1_sp); }
std::vector<uint8_t> SP::get_pk1_serialized() const  { return ps::serialize_ep(pk1); }
void SP::export_psk1_psk2(ep_t &out_psk1, gt_t &out_psk2) const {
        ep_copy(out_psk1, psk1_sp);
        gt_copy(out_psk2, psk2_sp);
}
void SP::export_spparams(ps::SPPublicParams &out_params) const {
    ep_copy(out_params.psk1_sp , psk1_sp);
    gt_copy(out_params.psk2_sp , psk2_sp);
}
} // namespace ps