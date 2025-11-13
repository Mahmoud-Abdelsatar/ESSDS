// #include "ps_crypto.hpp"
#include "ta.hpp"
#include "sp.hpp"
#include "vehicle.hpp"
#include "edge.hpp"
#include <iostream>

using namespace ps;

int main() {
    try {
        ps::init_relic();

        TA ta; ta.setup();
        ps::GlobalParams gp;
        ta.export_global_params(gp);
        std::cout << "TA initialized global parameters." << std::endl;


        SP sp("sp1"); sp.init_keys();
        sp.set_global_params(gp);
        ps::SPPublicParams spp;
        sp.export_spparams(spp);
        std::cout << "SP initialized and set global parameters." << std::endl;

        Edge edge;
        edge.setSPParams(spp);
        std::cout << "Edge initialized and set SP parameters." << std::endl;

        Vehicle v("veh1");
        v.setSPParams(spp);
        v.setGlobalParams(gp);
        std::cout << "Vehicle initialized and set SP and global parameters." << std::endl;


        ps::GroupSecretMaterial gsm = sp.generate_group_material_for_vehicle();
        v.recieve_group_secret_material(gsm);
        std::cout << "Vehicle received group secret material." << std::endl;


        // // Simulate group material distribution (application should perform authenticated DH session)
        // bn_t xi; bn_null(xi); bn_new(xi); 
        // bn_rand_mod(xi, bn_get_mod());
        // ep_t w1; ep_null(w1); ep_new(w1); 
        // ep2_t w2; ep2_null(w2); ep2_new(w2);
        // // In real flow compute w1 = h^{x_i+sk} and w2=A^{1/(x_i+sk)}; here we randomly set
        // ep_rand(w1); ep2_rand(w2);
        // v.receive_group_material(xi, w1, w2);

        // SP generates reenc key and edge accepts
        auto rk_ser = sp.generate_reenc_key();
        bool ok = edge.accept_reenc_key(rk_ser, 1);
        std::cout << "Edge accepted reenc? " << ok << std::endl;

        // SP signcrypts a message
        std::string message = "Hello, this is a secret message.";
        std::vector<uint8_t> mvec(message.begin(), message.end());
        uint64_t SN = 1;
        auto ct_ser = sp.signcrypt(mvec, SN);
        std::cout << "SP signcrypted message, CT size = " << ct_ser.size() << " bytes." << std::endl; 
        // Edge re-encrypts c1 to gt and forms re-encrypted CT
        auto reen_ct_ser = edge.receive_reencrypted_ct(ct_ser);
        std::cout << "Edge re-encrypted CT, size = " << reen_ct_ser.size() << " bytes." << std::endl;   
        // Vehicle unsigncrypts
        bool ver = v.unsigncrypt(reen_ct_ser);
        std::cout << "Vehicle unsigncrypt result: " << ver << std::endl;      
        ps::cleanup_relic();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}