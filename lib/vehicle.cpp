#include "vehicle.hpp"
#include <iostream>
namespace ps {

Vehicle::Vehicle(const std::string &id): id(id) { bn_null(x_i); bn_new(x_i); ep_null(w1); ep_new(w1); ep_null(w2); ep2_new(w2); 
ep_null(g1_);ep_new(g1_);ep_curve_get_gen(g1_);
ep2_null(g2_);ep2_new(g2_); ep2_curve_get_gen(g2_);
gt_null(z_); gt_new(z_);
pc_map(z_,g1_,g2_); 
}
Vehicle::~Vehicle() { /* free resources */ }

void Vehicle::setSPParams(const ps::SPPublicParams &params){ sp_params_ = params; }
void Vehicle::setSPParams_from_file(const std::string &filename) {
    sp_params_.import_from_file(filename);
}

void Vehicle::setGlobalParams(const ps::GlobalParams &params) { gp_params_ = params; }
void Vehicle::setGlobalParams_from_file(const std::string &filename) {
    gp_params_.import_from_file(filename);
}

void Vehicle::receive_group_material(const bn_t &x, const ep_t &w1_in, const ep2_t &w2_in) {
    bn_copy(x_i, x);
    ep_copy(w1, w1_in);
    ep2_copy(w2, w2_in);
    gt_t e; gt_null(e); gt_new(e);
    pc_map(e, w1, w2);
    gsk_sym = derive_key_from_gt(e);
    gt_free(e);
}
void Vehicle::recieve_group_secret_material(const ps::GroupSecretMaterial &gsm) {
    bn_copy(x_i, gsm.x);
    ep_copy(w1, gsm.w1);
    ep2_copy(w2, gsm.w2);
    gt_t e; gt_null(e); gt_new(e);
    pc_map(e, w1, w2);
    gsk_sym = derive_key_from_gt(e);
    gt_free(e);
    std::string hex;
    for (auto b : gsk_sym) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "SP: derived gsk key = " << hex << std::endl;   
}
void Vehicle::receive_group_secret_material_serialized(const std::vector<uint8_t>& gsm_ser) {
    bn_t order;
    ep_curve_get_ord(order);

    size_t bn_len = bn_size_bin(order);
    size_t ep_len = ep_size_bin(w1, 1);
    size_t ep2_len= ep2_size_bin(w2,1);
    
    std::cout<<"Lengths of bn:"<<bn_len<<", ep"<<ep_len<<", ep2"<<ep2_len<<std::endl;

    size_t offset=0;
    bn_read_bin(x_i, gsm_ser.data() + offset, bn_len);
    offset += bn_len;
    std::cout<<"xi is read"<<std::endl;
    ep_read_bin(w1, gsm_ser.data() + offset, ep_len);
    offset += ep_len;
    std::cout<<"w1 is read"<<std::endl;
    ep2_read_bin(w2, gsm_ser.data() + offset, ep2_len);

    std::cout << "Vehicle " << id << " received group secret material." << std::endl;
    // derive gsk_sym
    gt_t e; gt_null(e); gt_new(e);
    pc_map(e, w1, w2);
    gsk_sym = derive_key_from_gt(e);
    gt_free(e);
    std::string hex;
    for (auto b : gsk_sym) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "SP: derived gsk key = " << hex << std::endl;   
}
bool Vehicle::unsigncrypt(const gt_t &c1prime, const std::vector<uint8_t> &c2_ct, const std::vector<uint8_t>& c2_iv, const std::vector<uint8_t>& c2_tag, const bn_t &SN, const bn_t &t1, const bn_t &s, const ep_t &psk1_sp, const gt_t &psk2_sp) {
    // TODO: implement full check; current implementation tries to decrypt AES using derived key
    // derive z^{x1} = c1prime^{1/gsk}
    bn_t gsk_bn; bn_null(gsk_bn); bn_new(gsk_bn);
    auto tmp = kdf_sha256_to_32(gsk_sym);
    bn_read_bin(gsk_bn, tmp.data(), (int)tmp.size());

    gt_t z_x1; gt_null(z_x1); gt_new(z_x1);
    gt_exp(z_x1, c1prime, gsk_bn);
    auto symk = derive_key_from_gt(z_x1);
    AesGcmPack pack{c2_ct, c2_iv, c2_tag};
    std::vector<uint8_t> out;
    bool ok = aes_gcm_decrypt(symk, pack, out);
    if (!ok) {
        std::cerr << "Vehicle: decryption failed" << std::endl;
        gt_free(z_x1); bn_free(gsk_bn);
        return false;
    }
    std::cout << "Vehicle recovered plaintext (len=" << out.size() << ")" << std::endl;
    gt_free(z_x1); bn_free(gsk_bn);
    return true;
}
bool Vehicle::unsigncrypt(const std::vector<uint8_t>& ct_ser) {
    gt_t c1prime; gt_null(c1prime); gt_new(c1prime);
    bn_t s; bn_null(s); bn_new(s); 
    size_t bn_size = bn_size_bin(x_i);
    size_t gt_size = gt_size_bin(gp_params_.z, 1);
    std::cout << "Vehicle: bn size = " << bn_size << ", gt size = " << gt_size << " bytes.\n";
    // size_t ep_size = ep_size_bin(nullptr, 1);
    // parse ct_ser as [iv (16 bytes)][t1 (32 bytes)][s (bn size)][c1' (gt size)][c2_ct (rest)]
    size_t offset = 0;
    std::vector<uint8_t> iv(ct_ser.begin(), ct_ser.begin()+16);
    offset += 16;
    std::cout << "Vehicle: read iv of size " << iv.size() << " bytes.\n";
    std::vector<uint8_t> t1_bytes(ct_ser.begin()+offset, ct_ser.begin()+offset+32);
    offset += 32;
    std::cout << "Vehicle: read t1 hash of size " << t1_bytes.size() << " bytes.\n";
    std::vector<uint8_t> s_bytes(ct_ser.begin()+offset, ct_ser.begin()+offset+bn_size);
    offset += bn_size;
    std::cout << "Vehicle: read s scalar of size " << s_bytes.size() << " bytes.\n";
    // read SN from binary
    uint64_t SN = 0;
    for (int i=0; i<8; ++i) {
        SN = (SN << 8) | ct_ser[offset + i];
    }
    offset += 8;
    std::cout << "Vehicle: read SN = " << SN << std::endl;
    std::vector<uint8_t> c1prime_bytes;
    int gt_len = gt_size; // get GT size
    c1prime_bytes.insert(c1prime_bytes.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+gt_len);
    offset += gt_len;
    std::cout << "Vehicle: read c1' of size " << c1prime_bytes.size() << " bytes.\n";
    std::vector<uint8_t> c2_ct(ct_ser.begin()+offset, ct_ser.end());
    std::cout << "Vehicle: read c2 ciphertext of size " << c2_ct.size() << " bytes.\n";
    // compute z^x1 = (c1')^{1/gsk}
    gt_read_bin(c1prime, c1prime_bytes.data(), (int)c1prime_bytes.size());
    // reconstruct s
    bn_read_bin(s, s_bytes.data(), (int)s_bytes.size());
    // compute z^{x1} = (c1')^{1/gsk_sym}
    bn_t gsk_bn; bn_null(gsk_bn); bn_new(gsk_bn);
    // auto tmp = kdf_sha256_to_32(gsk_sym);
    // auto tmp = ps::kdf_sha256_to_32(gsk_sym);
    bn_read_bin(gsk_bn, gsk_sym.data(), (int)gsk_sym.size());

    // compute 1/gsk_bn mod order
    bn_t order; bn_null(order); bn_new(order);
    ep_curve_get_ord(order);
    bn_t gsk_inv; bn_null(gsk_inv); bn_new(gsk_inv);
    bn_mod_inv(gsk_inv, gsk_bn, order);

    gt_t z_x1; gt_null(z_x1); gt_new(z_x1);
    gt_exp(z_x1, c1prime, gsk_inv);
    // cout z_x1 in hex for debug
    std::string hex;
    int zlen = gt_size_bin(z_x1, 1);
    std::vector<uint8_t> zbuf(zlen);
    gt_write_bin(zbuf.data(), zlen, z_x1, 1);
    for (auto b : zbuf) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "Vehicle: z^{x1} = " << hex << std::endl;  

    auto symk = derive_key_from_gt(z_x1);
    // cout the symk value in hex for debug
    std::string hex2;
    for (auto b : symk) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex2 += buf;
    }
    std::cout << "Vehicle: derived sym key = " << hex2 << std::endl;
    // cout iv value in hex for debug
    std::string iv_hex;
    for (auto b : iv) {                
        char buf[3];
        sprintf(buf, "%02x", b);
        iv_hex += buf;
    }
    std::cout << "Vehicle: iv = " << iv_hex << std::endl;
    // try to decrypt c2_ct using symk using ps::aes_cbc_decrypt for legacy compatibility
    auto plain = ps::aes_cbc_decrypt(c2_ct, symk, iv);
    if (plain.empty()) {
        std::cerr << "Vehicle: decryption failed" << std::endl;
        gt_free(c1prime); bn_free(s); gt_free(z_x1); bn_free(gsk_bn);
        return false;
    }
    std::cout << "Vehicle recovered plaintext (len=" << plain.size() << ")" << std::endl;
    // parse plain as message
    std::string message((char*)plain.data(), plain.size());
    std::cout << "Vehicle recovered message: " << message << std::endl;
    // get z^x2 from the end of plain
    // int zlen = gt_size_bin(nullptr, 1);
    std::vector<uint8_t> z2buf(plain.end()-zlen, plain.end());
    gt_t z_x2; gt_null(z_x2); gt_new(z_x2);
    gt_read_bin(z_x2, z2buf.data(), (int)z2buf.size());
    // compute t0hash_bytes = ps::kdf_sha256_to_32(m)
    std::string m = message.substr(0, message.size()-zlen);
    std::cout << "Vehicle: extracted message m: " << m << std::endl;
    auto t0hash_bytes = ps::kdf_sha256_to_32(std::vector<uint8_t>(m.begin(), m.end()));
    // compute t2=H(t0||t1||c2||SN) using ps::kdf_sha256_to_32 for legacy compatibility
    std::vector<uint8_t> t2in;
    // append t0hash_bytes
    t2in.insert(t2in.end(), t0hash_bytes.begin(), t0hash_bytes.end());
    // append t1hash_bytes
    t2in.insert(t2in.end(), t1_bytes.begin(), t1_bytes.end());
    // append c2 bytes
    t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) {
        t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    }
    auto t2hash_bytes = ps::kdf_sha256_to_32(t2in);
    // cout t2hash_bytes in hex for debug
    std::string t2hex;
    for (auto b : t2hash_bytes) {           
        char buf[3];
        sprintf(buf, "%02x", b);
        t2hex += buf;
    }
    std::cout << "Vehicle: computed t2 hash = " << t2hex << std::endl;  
    // check {{z^{x1} \cdot z^{x2}}^t2 \cdot psk2_sp}^s ==z
    bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    bn_read_bin(t2bn, t2hash_bytes.data(), (int)t2hash_bytes.size());
    // get bn order
    // bn_t order; bn_null(order); bn_new(order);
    // ep_curve_get_ord(order);
    bn_mod(t2bn, t2bn, order);
    gt_t left, right, temp1, temp2;
    gt_null(left); gt_new(left);
    gt_null(right); gt_new(right);
    gt_null(temp1); gt_new(temp1);
    gt_null(temp2); gt_new(temp2);
    // compute z^{x1} * z^{x2}  
    gt_mul(temp1, z_x1, z_x2);
    // compute (z^{x1} * z^{x2})^{t2}
    gt_exp(temp2, temp1, t2bn);
    // compute (z^{x1} * z^{x2})^{t2} * psk2_sp
    gt_mul(left, temp2, sp_params_.psk2_sp);
    // compute {{z^{x1} * z^{x2}}^{t2} * psk2_sp}^{s}
    gt_exp(left, left, s);
    // right = z
    // compute z by getting g1 and g2 from ep_curve_get_gen and ep2_curve_get_gen
    ep_t g1; ep_null(g1); ep_new(g1); ep_curve_get_gen(g1);
    ep2_t g2; ep2_null(g2); ep2_new(g2); ep2_curve_get_gen(g2);
    pc_map(right, g1, g2);
    // gt_copy(right, gp_params_.z);
    bool res = (gt_cmp(left, right) == RLC_EQ);
    if (res) {  
        std::cout << "Vehicle: signature verified successfully." << std::endl;
    } else {
        std::cerr << "Vehicle: signature verification failed." << std::endl;
    }       

    // convert t2hash_bytes to bn
    // free
    gt_free(z_x1); bn_free(gsk_bn);
    gt_free(c1prime); bn_free(s);
    gt_free(z_x2);
    bn_free(t2bn);
    gt_free(left); gt_free(right); gt_free(temp1); gt_free(temp2);  

    // // reconstruct c1prime
    // gt_t c1prime; gt_null(c1prime); gt_new(c1prime);
    // pc_map(c1prime, gp_params_.g1, gp_params_.g2); // dummy init
    // gt_read_bin(c1prime, c1prime_bytes.data(), (int)c1prime_bytes.size());
    // // reconstruct s
    // bn_t s; bn_null(s); bn_new(s);
    // bn_read_bin(s, s_bytes.data(), (int)s_bytes.size());
    // 
    // // call main unsigncrypt
    // bool res = unsigncrypt(c1prime, c2_ct, iv, std::vector<uint8_t>(), bn_null(), bn_null(), s, ep_null(), gt_null());
    // gt_free(c1prime); bn_free(s);
    return res;
}
bool Vehicle::unsigncrypt(const std::vector<uint8_t>& ct_ser, std::vector<uint8_t>& out_message) {
    gt_t c1prime; gt_null(c1prime); gt_new(c1prime);
    bn_t s; bn_null(s); bn_new(s); 
    size_t bn_size = bn_size_bin(x_i);
    size_t gt_size = gt_size_bin(z_, 1);
    std::cout << "Vehicle: bn size = " << bn_size << ", gt size = " << gt_size << " bytes.\n";
    // size_t ep_size = ep_size_bin(nullptr, 1);
    // parse ct_ser as [iv (16 bytes)][t1 (32 bytes)][s (bn size)][c1' (gt size)][c2_ct (rest)]
    size_t offset = 0;
    std::vector<uint8_t> iv(ct_ser.begin(), ct_ser.begin()+16);
    offset += 16;
    std::cout << "Vehicle: read iv of size " << iv.size() << " bytes.\n";
    std::vector<uint8_t> t1_bytes(ct_ser.begin()+offset, ct_ser.begin()+offset+32);
    offset += 32;
    std::cout << "Vehicle: read t1 hash of size " << t1_bytes.size() << " bytes.\n";
    std::vector<uint8_t> s_bytes(ct_ser.begin()+offset, ct_ser.begin()+offset+bn_size);
    offset += bn_size;
    std::cout << "Vehicle: read s scalar of size " << s_bytes.size() << " bytes.\n";
    // read SN from binary
    uint64_t SN = 0;
    for (int i=0; i<8; ++i) {
        SN = (SN << 8) | ct_ser[offset + i];
    }
    offset += 8;
    std::cout << "Vehicle: read SN = " << SN << std::endl;
    std::vector<uint8_t> c1prime_bytes;
    int gt_len = gt_size; // get GT size
    c1prime_bytes.insert(c1prime_bytes.end(), ct_ser.begin()+offset, ct_ser.begin()+offset+gt_len);
    offset += gt_len;
    std::cout << "Vehicle: read c1' of size " << c1prime_bytes.size() << " bytes.\n";
    std::vector<uint8_t> c2_ct(ct_ser.begin()+offset, ct_ser.end());
    std::cout << "Vehicle: read c2 ciphertext of size " << c2_ct.size() << " bytes.\n";
    // compute z^x1 = (c1')^{1/gsk}
    gt_read_bin(c1prime, c1prime_bytes.data(), (int)c1prime_bytes.size());
    // reconstruct s
    bn_read_bin(s, s_bytes.data(), (int)s_bytes.size());
    // compute z^{x1} = (c1')^{1/gsk_sym}
    bn_t gsk_bn; bn_null(gsk_bn); bn_new(gsk_bn);
    // auto tmp = kdf_sha256_to_32(gsk_sym);
    // auto tmp = ps::kdf_sha256_to_32(gsk_sym);
    bn_read_bin(gsk_bn, gsk_sym.data(), (int)gsk_sym.size());

    // compute 1/gsk_bn mod order
    bn_t order; bn_null(order); bn_new(order);
    ep_curve_get_ord(order);
    bn_t gsk_inv; bn_null(gsk_inv); bn_new(gsk_inv);
    bn_mod_inv(gsk_inv, gsk_bn, order);

    gt_t z_x1; gt_null(z_x1); gt_new(z_x1);
    gt_exp(z_x1, c1prime, gsk_inv);
    // cout z_x1 in hex for debug
    std::string hex;
    int zlen = gt_size_bin(z_x1, 1);
    std::vector<uint8_t> zbuf(zlen);
    gt_write_bin(zbuf.data(), zlen, z_x1, 1);
    for (auto b : zbuf) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex += buf;
    }
    std::cout << "Vehicle: z^{x1} = " << hex << std::endl;  

    auto symk = derive_key_from_gt(z_x1);
    // cout the symk value in hex for debug
    std::string hex2;
    for (auto b : symk) {
        char buf[3];
        sprintf(buf, "%02x", b);
        hex2 += buf;
    }
    std::cout << "Vehicle: derived sym key = " << hex2 << std::endl;
    // cout iv value in hex for debug
    std::string iv_hex;
    for (auto b : iv) {                
        char buf[3];
        sprintf(buf, "%02x", b);
        iv_hex += buf;
    }
    std::cout << "Vehicle: iv = " << iv_hex << std::endl;
    // try to decrypt c2_ct using symk using ps::aes_cbc_decrypt for legacy compatibility
    auto plain = ps::aes_cbc_decrypt(c2_ct, symk, iv);
    if (plain.empty()) {
        std::cerr << "Vehicle: decryption failed" << std::endl;
        gt_free(c1prime); bn_free(s); gt_free(z_x1); bn_free(gsk_bn);
        return false;
    }
    std::cout << "Vehicle recovered plaintext (len=" << plain.size() << ")" << std::endl;
    // parse plain as message
    std::string message((char*)plain.data(), plain.size());
    std::cout << "Vehicle recovered message: " << message << std::endl;
    // get z^x2 from the end of plain
    // int zlen = gt_size_bin(nullptr, 1);
    std::vector<uint8_t> z2buf(plain.end()-zlen, plain.end());
    gt_t z_x2; gt_null(z_x2); gt_new(z_x2);
    gt_read_bin(z_x2, z2buf.data(), (int)z2buf.size());
    // compute t0hash_bytes = ps::kdf_sha256_to_32(m)
    std::string m = message.substr(0, message.size()-zlen);
    std::cout << "Vehicle: extracted message m: " << m << std::endl;
    // copy m to out_message
    out_message.assign(m.begin(), m.end());

    auto t0hash_bytes = ps::kdf_sha256_to_32(std::vector<uint8_t>(m.begin(), m.end()));
    // compute t2=H(t0||t1||c2||SN) using ps::kdf_sha256_to_32 for legacy compatibility
    std::vector<uint8_t> t2in;
    // append t0hash_bytes
    t2in.insert(t2in.end(), t0hash_bytes.begin(), t0hash_bytes.end());
    // append t1hash_bytes
    t2in.insert(t2in.end(), t1_bytes.begin(), t1_bytes.end());
    // append c2 bytes
    t2in.insert(t2in.end(), c2_ct.begin(), c2_ct.end());
    // append SN as 8 bytes BE
    for (int i=7; i>=0; --i) {
        t2in.push_back((uint8_t)((SN >> (8*i)) & 0xFF));
    }
    auto t2hash_bytes = ps::kdf_sha256_to_32(t2in);
    // cout t2hash_bytes in hex for debug
    std::string t2hex;
    for (auto b : t2hash_bytes) {           
        char buf[3];
        sprintf(buf, "%02x", b);
        t2hex += buf;
    }
    std::cout << "Vehicle: computed t2 hash = " << t2hex << std::endl;  
    // check {{z^{x1} \cdot z^{x2}}^t2 \cdot psk2_sp}^s ==z
    bn_t t2bn; bn_null(t2bn); bn_new(t2bn);
    bn_read_bin(t2bn, t2hash_bytes.data(), (int)t2hash_bytes.size());
    // get bn order
    // bn_t order; bn_null(order); bn_new(order);
    // ep_curve_get_ord(order);
    bn_mod(t2bn, t2bn, order);
    gt_t left, right, temp1, temp2;
    gt_null(left); gt_new(left);
    gt_null(right); gt_new(right);
    gt_null(temp1); gt_new(temp1);
    gt_null(temp2); gt_new(temp2);
    // compute z^{x1} * z^{x2}  
    gt_mul(temp1, z_x1, z_x2);
    // compute (z^{x1} * z^{x2})^{t2}
    gt_exp(temp2, temp1, t2bn);
    // compute (z^{x1} * z^{x2})^{t2} * psk2_sp
    gt_mul(left, temp2, sp_params_.psk2_sp);
    // compute {{z^{x1} * z^{x2}}^{t2} * psk2_sp}^{s}
    gt_exp(left, left, s);
    // right = z
    // compute z by getting g1 and g2 from ep_curve_get_gen and ep2_curve_get_gen
    // ep_t g1; ep_null(g1); ep_new(g1); ep_curve_get_gen(g1);
    // ep2_t g2; ep2_null(g2); ep2_new(g2); ep2_curve_get_gen(g2);
    // pc_map(right, g1, g2);
    // gt_copy(right, gp_params_.z);
    bool res = (gt_cmp(left, z_) == RLC_EQ);
    if (res) {  
        std::cout << "Vehicle: signature verified successfully." << std::endl;
    } else {
        std::cerr << "Vehicle: signature verification failed." << std::endl;
    }       

    // convert t2hash_bytes to bn
    // free
    gt_free(z_x1); bn_free(gsk_bn);
    gt_free(c1prime); bn_free(s);
    gt_free(z_x2);
    bn_free(t2bn);
    gt_free(left); gt_free(right); gt_free(temp1); gt_free(temp2);  

    // // reconstruct c1prime
    // gt_t c1prime; gt_null(c1prime); gt_new(c1prime);
    // pc_map(c1prime, gp_params_.g1, gp_params_.g2); // dummy init
    // gt_read_bin(c1prime, c1prime_bytes.data(), (int)c1prime_bytes.size());
    // // reconstruct s
    // bn_t s; bn_null(s); bn_new(s);
    // bn_read_bin(s, s_bytes.data(), (int)s_bytes.size());
    // 
    // // call main unsigncrypt
    // bool res = unsigncrypt(c1prime, c2_ct, iv, std::vector<uint8_t>(), bn_null(), bn_null(), s, ep_null(), gt_null());
    // gt_free(c1prime); bn_free(s);
    return res;
}
} // namespace ps