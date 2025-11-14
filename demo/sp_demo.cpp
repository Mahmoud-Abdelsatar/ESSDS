#include<iostream>
#include<chrono>
#include<utility>
#include <cmath>
#include <numeric>
#include <vector>
#include <sstream>
#include <iomanip>
#include "sp.hpp"
#include "socketmanager.hpp"

using namespace ps;
using namespace std;
template <typename F>
std::pair<double, double> benchmark_stats(F func, int inner_loop = 100, int outer_loop = 1000) {
    vector<double> times;
    times.reserve(outer_loop);

    for (int i = 0; i < outer_loop; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < inner_loop; ++j) func();
        auto end = std::chrono::high_resolution_clock::now();
        double total = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        times.push_back(total / inner_loop);
    }

    double sum = 0.0;
    for (double t : times) sum += t;
    double mean = sum / outer_loop;

    double sq_sum = 0.0;
    for (double t : times) sq_sum += (t - mean) * (t - mean);
    double stddev = sqrt(sq_sum / outer_loop);

    return {mean, stddev};
}

bool send_reenc_key_to_edge(const std::vector<uint8_t>& rk_ser) {
    // Placeholder: actual network code to send rk_ser to edge server
    std::cout << "Sending re-encryption key to edge server, size = " << rk_ser.size() << " bytes." << std::endl;
    // e.g., open TCP connection, send data, close connection
    int sock=SocketManager::connectTo("127.0.0.1", 5000);
    SocketManager::sendData(sock, rk_ser);
    SocketManager::closeSock(sock);
    return true;
}
bool send_ct_to_edge(const std::vector<uint8_t>& ct_ser) {
    // Placeholder: actual network code to send ct_ser to edge server
    std::cout << "Sending ciphertext to edge server, size = " << ct_ser.size() << " bytes." << std::endl;
    // e.g., open TCP connection, send data, close connection
    int sock=SocketManager::connectTo("127.0.0.1", 5000);
    SocketManager::sendData(sock, ct_ser);
    std::vector<uint8_t> ack=SocketManager::recvData(sock);
    SocketManager::closeSock(sock);
    return true;
}
bool send_group_material_to_vehicle(const std::vector<uint8_t>& enc_gm_ser) {
    // Placeholder: actual network code to send enc_gm_ser to Vehicle
    std::cout << "Sending encrypted group secret material to Vehicle, size = " << enc_gm_ser.size() << " bytes." << std::endl;
    // e.g., open TCP connection, send data, close connection
    int srcok=SocketManager::createServer(5001);
    int client=SocketManager::acceptClient(srcok);
    std::vector<uint8_t> request=SocketManager::recvData(client); // receive request
    SocketManager::sendData(client, enc_gm_ser);
    SocketManager::closeSock(client);
    SocketManager::closeSock(srcok);
    return true;
}
bool export_public_key(const std::vector<uint8_t>& spparams_ser)
{
    std::cout<<"Waiting to export the public key"<<std::endl;
    int srcok=SocketManager::createServer(5001);
    int client=SocketManager::acceptClient(srcok);
    std::vector<uint8_t> request=SocketManager::recvData(client); // receive request
    SocketManager::sendData(client, spparams_ser);
    SocketManager::closeSock(client);
    SocketManager::closeSock(srcok);
    return true;
}
std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}
void print_relic_curves_paramters()
{
    ep_t g1; ep_null(); ep_new(); ep_curve_get_gen(g1);
    ep2_t g2;ep2_null();ep2_new(); ep2_curve_get_gen(g2);
    gt_t gt; gt_null(); gt_new();
    pc_map(gt,g1,g2); 
    size_t ep_len=ep_size_bin(g1,1);
    ssize_t ep2_len=ep2_size_bin(g2,1);
    size_t gt_len=gt_size_bin(gt,1);
    std::cout<<"|G1|="<<ep_len<<std::endl;
    std::cout<<"|G2|"<<ep2_len<<std::endl;
    std::cout<<"|G_T|"<<gt_len<<std::endl;
    std::vector<uint8_t> g1_ser=ps::serialize_ep(g1);
    std::vector<uint8_t> g2_ser=ps::serialize_ep2(g2);
    std::vector<uint8_t> gt_ser=ps::serialize_gt(gt);
    std::cout << "G1 hex: " << to_hex(g1_ser) << std::endl;
    std::cout << "G2 hex: " << to_hex(g2_ser) << std::endl;
    std::cout << "GT hex: " << to_hex(gt_ser) << std::endl;
}
int main() {
    ps::init_relic();
    ps::set_static_generators();
    SP sp("sp1");
    sp.init_keys();
    std::cout << "SP initialized." << std::endl;
    // cout the Relic setup such as g1 and g2 as well as the sizes of lengths of G1 G2 and Gt
    print_relic_curves_paramters();    
    // ps::GlobalParams gp;
    // // sp.export_global_params(gp);
    // sp.set_global_params_from_file("global_params.dat");
    // std::cout << "SP set global parameters." << std::endl;
    ps::SPPublicParams spp;
    sp.export_spparams(spp);
    spp.export_to_file("sp_params.dat");
    std::cout << "SP exported public parameters to file." << std::endl;
    int n=0;
    do
    {
        // Here let select one of
        std::cout<<"Please select one of the following optopns:"<<std::endl;
        std::cout<<"1- Generate Re-encryption Key and send to Edge"<<std::endl;
        std::cout<<"2- Signcrypt a message and send ciphertext to Edge"<<std::endl;
        std::cout<<"3- Generate group secret material for Vehicle and send to Vehicle"<<std::endl;
        std::cout<<"4- (Benchmark) Signcrypt a message and send ciphertext to Edge"<<std::endl;
        std::cout<<"5- Export SP public key"<<std::endl;
        std::cout<<"-1- Exit"<<std::endl;
        std::cin >> n;
        if(n==1){
            // SP generates reenc key
            auto rk_ser = sp.generate_reenc_key();
            std::cout << "SP generated re-encryption key, size = " << rk_ser.size() << " bytes." << std::endl;  
            // SP opens tcp connection to edge and sends rk_ser
            send_reenc_key_to_edge(rk_ser);
        }
        else if(n==2){
            //SP signcrypts a message
            std::string message = "Hello, this is a secret message.";
            std::vector<uint8_t> mvec(message.begin(), message.end()); 
            uint64_t SN = 1;
            auto ct_ser = sp.signcrypt(mvec, SN);  
            std::cout << "SP signcrypted message, CT size = " << ct_ser.size() << " bytes." << std::endl;   
            // SP opens tcp connection to the edge and sends ct_ser
            send_ct_to_edge(ct_ser);
        }
        else if(n==3){
            // SP prepares group secret material for vehicle
            auto gsm_ser = sp.generate_group_material_serialized_for_vehicle();
            std::cout << "SP generated group secret material for vehicle, size = " << gsm_ser.size() << " bytes." << std::endl;  
            // SP opens tcp connection to vehicle and sends gsm_ser
            send_group_material_to_vehicle(gsm_ser);
        }  
        else if(n==4){
             
            //SP signcrypts a message
            std::string message = "Hello, this is a secret message.";
            std::vector<uint8_t> mvec(message.begin(), message.end()); 
            uint64_t SN = 1;
            auto [avg_ns, std_dev] = benchmark_stats([&]() {
            auto ct_ser = sp.signcrypt(mvec, SN);  
            std::cout << "SP signcrypted message, CT size = " << ct_ser.size() << " bytes." << std::endl;   
            // SP opens tcp connection to the edge and sends ct_ser
            send_ct_to_edge(ct_ser);
            });

            std::cout<<"The average end-to-end latency of signcryption and re-encryption including the network latecny:"<<avg_ns<<"|"<<std_dev<<std::endl;
        }
        else if(n==5)
        {
            std::vector<uint8_t> spparams_ser=spp.export_serialized();
            export_public_key(spparams_ser);
        }
    } while (n!=-1);
    
    // // SP generates reenc key
    // auto rk_ser = sp.generate_reenc_key();
    // std::cout << "SP generated re-encryption key, size = " << rk_ser.size() << " bytes." << std::endl;  
    // // SP opens tcp connection to edge and sends rk_ser
    // int n;
    // std::cin >> n;
    
    // // Placeholder: actual network code omitted for brevity

    // send_reenc_key_to_edge(rk_ser);

    // std::cin >> n;
    // //SP signcrypts a message
    // std::string message = "Hello, this is a secret message.";
    // std::vector<uint8_t> mvec(message.begin(), message.end());
    // uint64_t SN = 1;
    // auto ct_ser = sp.signcrypt(mvec, SN);
    // std::cout << "SP signcrypted message, CT size = " << ct_ser.size() << " bytes." << std::endl;   
    
    // std::cin >> n;
    // // SP opens tcp connection to the edge and sends ct_ser
    // // Placeholder: actual network code omitted for brevity
    // std::cout << "SP sent ciphertext to edge server." << std::endl; 
    // send_ct_to_edge(ct_ser);

    // std::cin >> n;
    // // SP prepares group secret material for vehicle
    // auto gsm_ser = sp.generate_group_material_serialized_for_vehicle();
    // std::cout << "SP generated group secret material for vehicle, size = " << gsm_ser.size() << " bytes." << std::endl;  
    // // SP opens tcp connection to vehicle and sends gsm_ser
    // std::cin >> n;  
    // send_group_material_to_vehicle(gsm_ser);
    return 0;
}