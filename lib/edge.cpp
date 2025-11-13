#include "edge.hpp"
#include <iostream>
namespace ps {

Edge::Edge() { ep2_null(rk); ep2_new(rk); LSN = 0; ep_null(g1_);ep_new(g1_);ep_curve_get_gen(g1_);
ep2_null(g2_);ep2_new(g2_); ep2_curve_get_gen(g2_);
gt_null(z_); gt_new(z_);
pc_map(z_,g1_,g2_);}
Edge::~Edge() { /* free */ }

void Edge::setSPParams(const ps::SPPublicParams &params){ sp_params_ = params; }
void Edge::setSPParams_from_file(const std::string &filename) {
    sp_params_.import_from_file(filename);
}

bool Edge::accept_reenc_key(const std::vector<uint8_t> &rk_ser, int SN) {
    // SN must equal LSN+1
    // 
    if (SN != LSN + 1) {
        std::cerr << "Edge: bad SN for rekey\n";
        return false;
    }
    //cout the rk_ser value in hex for debug
    std::string hex;
    for (auto b : rk_ser) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "Edge: received reenc key = " << hex << std::endl;

    // read rk 
    ep2_read_bin(rk, rk_ser.data(), (int)rk_ser.size());
    LSN = SN;
    return true;
}
// bool Edge::accept_signed_reenc_key(const std::vector<uint8_t> & rk_ser)
// {
//     ep_t R;
//     bn_t s;
//     ep_null(R); ep_new(R);
//     bn_null(s); bn_new(s); bn_rand(s); 
//     size_t bn_len=bn_size_bin(s);
//     size_t ep_len=ep_size_bin(g1_,1);
//     size_t ep2_len=ep2_size_bin(g2_,1);
//     size_t offset=0;
//     uint64_t SN=0;
//     ep2_read_bin(rk,rk_ser.data()+offset,ep2_len);
//     offset+=ep2_len;
//     memcpy(SN,rk_ser.data()+offset,sizeof(SN));
//     offset+=sizeof(SN);
//     ep_read_bin(R,rk_ser.data()+offset,ep_len);
//     offset+=ep_len;
//     bn_read_bin(s,rk_ser.data()+offset,bn_len);
//     if (SN != LSN + 1) {
//         std::cerr << "Edge: bad SN for rekey\n";
//         return false;
//     }
//     // Deserialize R and s
//     ps::ElGamalSignature sig;
//     ep_null(sig.R); ep_new(sig.R);
//     bn_null(sig.s); bn_new(sig.s);

//     ep_copy(sig.R, R);
//     bn_copy(sig.s, s);

//     // Recreate message = rk || SN
//     std::vector<uint8_t> msg(rk);
//     uint8_t sn_bytes[sizeof(SN)];
//     memcpy(sn_bytes, &SN, sizeof(SN));
//     msg.insert(msg.end(), sn_bytes, sn_bytes + sizeof(SN));

//     // Verify
//     return ps::elgamal_verify(msg, sig, sp_params_.psk1_sp, g1_);

// }

std::vector<uint8_t> Edge::reencrypt_c1_to_gt(const std::vector<uint8_t> &c1_ser) const {
    ep_t c1; ep_null(c1); ep_new(c1);
    ep_read_bin(c1, c1_ser.data(), (int)c1_ser.size());
    // ep2_t combined; ep2_null(combined); ep2_new(combined);
    // ep2_add_basic(combined, c1, rk);
    // ep_t g1; ep_null(g1); ep_new(g1); ep_curve_get_gen(g1);
    gt_t out; gt_null(out); gt_new(out);
    pc_map(out, c1, rk);
    auto ser = ps::serialize_gt(out);
    ep2_free(c1); ep2_free(combined); ep_free(g1); gt_free(out);
    return ser;
}
std::vector<uint8_t> Edge::receive_reencrypted_ct(const std::vector<uint8_t> &ct_ser) {
    //get ep cuver order
    bn_t order; bn_null(order); bn_new(order);
    ep_curve_get_ord(order);
    // get ep curver generator g
    ep_t g1_; ep_null(g1_); ep_new(g1_); ep_curve_get_gen(g1_);
    std::cout << "Edge: processing re-encrypted CT of size " << ct_ser.size() << " bytes.\n";
    size_t ep_size = ep_size_bin(g1_,1);
    size_t bn_size = bn_size_bin(order);
    std::cout << "Edge: ep size = " << ep_size << ", bn size = " << bn_size << " bytes.\n";
    // placeholder: full implementation will follow in next step
    // read [iv] [t0hx] [R] [s] [c1] [c2] from ct_ser
    std::vector<uint8_t> iv;
    std::vector<uint8_t> t0bytes;
    std::vector<uint8_t> R_ser;
    std::vector<uint8_t> s_ser;
    std::vector<uint8_t> c1_ser;
    std::vector<uint8_t> c2_ct;
    // read iv (16 bytes)
    iv.insert(iv.end(), ct_ser.begin(), ct_ser.begin()+16);
    size_t iv_size = 16;
    size_t offset = 16;
    std::cout << "Edge: read iv of size " << iv_size << " bytes.\n";
    // read t0hex (32 bytes)
    t0bytes.insert(t0bytes.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+32); // assuming sha256 bytes
    offset+=32;
    std::cout << "Edge: read t0 hash of size " << t0bytes.size() << " bytes.\n";
    // std::cout << "ep size= "<< ep_size_bin(nullptr,1) << ", bn size=" << bn_size_bin(nullptr) << std::endl;
    R_ser.insert(R_ser.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+ep_size);
    offset += ep_size;
    std::cout << "Edge: read R of size " << R_ser.size() << " bytes.\n";
    s_ser.insert(s_ser.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+bn_size);
    offset += bn_size;
    std::cout << "Edge: read s of size " << s_ser.size() << " bytes.\n";
    // read SN from binary
    uint64_t SN = 0;
    for (int i=0; i<8; ++i) {
        SN = (SN << 8) | ct_ser[offset + i];
    }
    offset += 8;
    std::cout << "Edge: read SN = " << SN << ".\n";
    c1_ser.insert(c1_ser.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+ep_size);
    offset += ep_size;
    std::cout << "Edge: read c1 of size " << c1_ser.size() << " bytes.\n";
    c2_ct.insert(c2_ct.end(), ct_ser.begin()+offset, ct_ser.end());
    std::cout << "Edge: read c2 ciphertext of size " << c2_ct.size() << " bytes.\n";
    // for now just print sizes
    std::cout << "Edge: received re-encrypted CT parts sizes: t0hex=" << t0bytes.size()
              << " R_ser=" << R_ser.size()
              << " s_ser=" << s_ser.size()
              << " SN=" << SN
              << " c1_ser=" << c1_ser.size()
              << " c2_ct=" << c2_ct.size() << std::endl; 
     
    // compute t1=H(c1) using ps::kdf_sha256_to_32 for legacy compatibility
    auto t1hash_bytes = ps::kdf_sha256_to_32(c1_ser);
    std::string t1hex;
    for (auto b : t1hash_bytes) {
        char buf[3];
        sprintf(buf, "%02x", b);
        t1hex += buf;
    }
    // CryptoUtils cu;
    // std::string c1str((char*)c1_ser.data(), c1_ser.size());
    // std::string t1hex = ps::kdf_sha256_to_32(c1_ser); 
    //  std::string c1str((char*)c1_ser.data(), c1_ser.size());
    //  std::string t1hex = cu.sha256(c1str);
        std::cout << "Edge: computed t1 hash = " << t1hex << std::endl;
    // compute t2=H(t0||t1||c2||SN)
    std::vector<uint8_t> t2in;
    // append t0hash_bytes
    t2in.insert(t2in.end(), t0bytes.begin(), t0bytes.end());
    // append t1hash_bytes
    t2in.insert(t2in.end(), t1hash_bytes.begin(), t1hash_bytes.end());
    // append c2 bytes
    t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) {
        t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    }
    auto t2hash_bytes = ps::kdf_sha256_to_32(t2in);
    std::string t2hex;
    for (auto b : t2hash_bytes) {
        char buf[3];
        sprintf(buf, "%02x", b);
        t2hex += buf;
    }
        std::cout << "Edge: computed t2 hash = " << t2hex << std::endl; 
    // convert t2hash_bytes to bn
    bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    bn_read_bin(t2bn, t2hash_bytes.data(), (int)t2hash_bytes.size());
    bn_mod(t2bn, t2bn, order);
    // // compute t2=H(t0||t1||c2||SN) using ps::kdf_sha256_to_32 for legacy compatibility      
    // std::vector<uint8_t> t2in;
    // // append t0 bytes
    // for (size_t i=0; i<t0hex.size(); ++i) t2in.push_back((uint8_t)(t0hex[i]));
    // // append t1 bytes
    // for (size_t i=0; i<t1hex.size(); ++i) t2in.push_back((uint8_t)(t1hex[i]));
    // // append c2 bytes
    // t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // // append SN as 8 bytes BE
    // for (int i=7; i>=0; --i) t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    // std::string t2hex = cu.sha256(std::string((char*)t2in.data(), t2in.size()));
    //     std::cout << "Edge: computed t2 hash = " << t2hex << std::endl; 
    // // check {psk1_sp * R^{t2}} ^ s == g
    // // convert t2hex to bn
    // bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    // std::vector<uint8_t> t2bytes;
    // for (size_t i=0; i<t2hex.size(); i+=2) {
    //     t2bytes.push_back((uint8_t)strtol(t2hex.substr(i,2).c_str(), nullptr, 16));
    // }
    // bn_read_bin(t2bn, t2bytes.data(), (int)t2bytes.size());
    // bn_mod(t2bn, t2bn, order_get());
    // read R from binary
    ep_t R; ep_null(R); ep_new(R);
    ep_read_bin(R, R_ser.data(), (int)R_ser.size());
    // read s from binary
    bn_t s; bn_null(s); bn_new(s);
    bn_read_bin(s, s_ser.data(), (int)s_ser.size());
    // compute R^{t2}
    ep_t R_t2; ep_null(R_t2); ep_new(R_t2);
    ep_mul(R_t2, R, t2bn);
    // compute psk1_sp * R^{t2}
    ep_t left; ep_null(left); ep_new(left);
    ep_add(left, sp_params_.psk1_sp, R_t2);
    // compute (psk1_sp * R^{t2})^s
    ep_t result; ep_null(result); ep_new(result);
    ep_mul(result, left, s);
    // check if result == g
    bool verified = (ep_cmp(result, g1_) == RLC_EQ);
    if (verified) {
        std::cout << "Edge: re-encrypted CT verified successfully.\n";
    } else {
        std::cerr << "Edge: re-encrypted CT verification failed!\n";       
    }
    // re-ecnrypt c1 to gt
    ep_t c1; ep_null(c1); ep_new(c1);
    ep_read_bin(c1, c1_ser.data(), (int)c1_ser.size());
    gt_t c1p; gt_null(c1p); gt_new(c1p);
    pc_map(c1p, c1, rk);
    std::cout<<"c1p size in gt: "<< gt_size_bin(c1p,1) << std::endl;
    auto c1p_ser = ps::serialize_gt(c1p);
    std::cout << "Edge: re-encrypted c1 to gt, size = " << c1p_ser.size() << " bytes.\n";   
    // form the re-encrypted CT structure to send to Vehicle as [iv][t1][s][c1'][c2]
    std::vector<uint8_t> out;
    // append iv bytes
    out.insert(out.end(), iv.begin(), iv.end());
    // append t1hash bytes
    out.insert(out.end(), t1hash_bytes.begin(), t1hash_bytes.end());
    // for (size_t i=0; i<t1hex.size(); ++i) 
    //     out.push_back((uint8_t)(t1hex[i]));
    out.insert(out.end(), s_ser.begin(), s_ser.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) 
        out.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    out.insert(out.end(), c1p_ser.begin(), c1p_ser.end());
    out.insert(out.end(), c2_ct.begin(), c2_ct.end());
    // free
    bn_free(t2bn); bn_free(s);
    ep_free(R); ep_free(R_t2); ep_free(left); ep_free(result); 
    return out;     
}
} // namespace ps