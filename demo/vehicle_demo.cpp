#include<iostream>
#include "vehicle.hpp"
#include "socketmanager.hpp"
#include<chrono>
#include<utility>
#include <cmath>
#include <numeric>
using namespace ps;
using namespace std;
template <typename F>
pair<double, double> benchmark_stats(F func, int inner_loop = 10, int outer_loop = 10) {
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
bool get_group_material_from_sp(std::vector<uint8_t>& enc_gm_ser) {
    // Placeholder: actual network code to receive enc_gm_ser from SP
    std::cout << "Receiving encrypted group secret material from SP." << std::endl;
    // e.g., open TCP connection, receive data, close connection
    int sock=SocketManager::connectTo("127.0.0.1",5001);
    // set string message "Subscription Request" in vector variable.
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), {'S','u','b','s','c','r','i','p','t','i','o','n',' ','R','e','q','u','e','s','t'});
    SocketManager::sendData(sock, msg);
    enc_gm_ser=SocketManager::recvData(sock);
    // cout the received enc_gm_ser size
    std::cout << "Vehicle: received encrypted group secret material of size " << enc_gm_ser.size() << " bytes." << std::endl;
    SocketManager::closeSock(sock);
    //
    return true;
}
bool get_reenc_ct_from_edge(std::vector<uint8_t>& reenc_ct_ser) {
    // Placeholder: actual network code to receive reenc_ct_ser from Edge
    std::cout << "Receiving re-encrypted ciphertext from Edge." << std::endl;
    // e.g., open TCP connection, receive data, close connection
    int sock=SocketManager::connectTo("127.0.0.1",5000);
    // set string message "Request Re-encrypted CT" in vector variable.
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), {'R','e','q','u','e','s','t',' ','R','e','-','e','n','c','r','y','p','t','e','d',' ','C','T'});
    SocketManager::sendData(sock, msg);
    reenc_ct_ser=SocketManager::recvData(sock);
    SocketManager::closeSock(sock);
    //     
    return true;
}
int main() {
    ps::init_relic();
    Vehicle v("veh1");
    ps::SPPublicParams spp;
    try
    {
        spp.import_from_file("sp_params.dat");
        v.setSPParams(spp);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return -1;
    }
    // spp.import_from_file("sp_params.dat");
    
   
    // ps::GlobalParams gp;
    // gp.import_from_file("global_params.dat");
    // v.setGlobalParams(gp);
    // std::cout << "Vehicle initialized and set SP and global parameters." << std::endl;
    int n=0;
    do
    {
        std::cout<<"Please select one of the following optopns:"<<std::endl;
        std::cout<<"1- Subscribe and receive group secret material from SP"<<std::endl;
        std::cout<<"2- Request and receive re-encrypted ciphertext from Edge"<<std::endl;
        std::cout<<"3- (Benchmarked) Request and receive re-encrypted ciphertext from Edge"<<std::endl;
        
        std::cout<<"-1- Exit"<<std::endl;
        std::cin >> n;
        if(n==1){
            // vehicle subscribes and receives group secret material from SP
            std::vector<uint8_t> enc_gm_ser; // placeholder: actual code to receive from network
            // For demo, we can read from file or assume enc_gm_ser is set
            bool ok=get_group_material_from_sp(enc_gm_ser);
            if(!ok)
            {
                std::cerr << "Vehicle failed to receive group secret material from SP." << std::endl;
                return -1;
            }
            // deserialize group secret material
            // ps::GroupSecretMaterial gsm;
            // placeholder: actual deserialization code
            // v.recieve_group_secret_material(gsm);
            v.receive_group_secret_material_serialized(enc_gm_ser);
            std::cout << "Vehicle received group secret material." << std::endl;
        }
        else if(n==2){
            // Vehicle connects to edge and requests re-encrypted ciphertext
            std::vector<uint8_t> reenc_ct_ser; // placeholder: actual code to receive from edge
            // For demo, we can read from file or assume reenc_ct_ser is set
            bool ok=get_reenc_ct_from_edge(reenc_ct_ser);
            if(!ok)
            {
                std::cerr << "Vehicle failed to receive re-encrypted ciphertext from Edge." << std::endl;
                return -1;
            }
            std::vector<uint8_t> out_message;
            ok = v.unsigncrypt(reenc_ct_ser, out_message);
            if(ok)
            {
                std::string recovered_msg(out_message.begin(), out_message.end());
                std::cout << "Vehicle successfully unsigncrypted the message: " << recovered_msg << std::endl;
            }
            else
            {
                std::cout << "Vehicle failed to unsigncrypt the message." << std::endl;
            }
        }
         else if(n==3){
            // Vehicle connects to edge and requests re-encrypted ciphertext
            std::vector<uint8_t> reenc_ct_ser; // placeholder: actual code to receive from edge
            // For demo, we can read from file or assume reenc_ct_ser is set
            auto [avg_ns, std_dev] = benchmark_stats([&]() {

                bool ok=get_reenc_ct_from_edge(reenc_ct_ser);
                if(!ok)
                {
                    std::cerr << "Vehicle failed to receive re-encrypted ciphertext from Edge." << std::endl;
                    return;
                }
                std::vector<uint8_t> out_message;
                ok = v.unsigncrypt(reenc_ct_ser, out_message);
                // if(ok)
                // {
                //     std::string recovered_msg(out_message.begin(), out_message.end());
                //     std::cout << "Vehicle successfully unsigncrypted the message: " << recovered_msg << std::endl;
                // }
                // else
                // {
                //     std::cout << "Vehicle failed to unsigncrypt the message." << std::endl;
                // }
            });
            std::cout<<"The average end-to-end latency to get and unsigncrypt the ciphertext:"<<avg_ns<<"|"<<std_dev<<std::endl;
        }     
    } while (n!=-1);
    
    // vehicle subsribes and receives group secret material from SP
    // Vehicle open tcp connection to SP and receives serliazed encrypted group material
    // std::vector<uint8_t> enc_gm_ser; // placeholder: actual code to receive from network
    // // For demo, we can read from file or assume enc_gm_ser is set
    // bool ok=get_group_material_from_sp(enc_gm_ser);
    // if(!ok)
    // {
    //     std::cerr << "Vehicle failed to receive group secret material from SP." << std::endl;
    //     return -1;
    // }
    // // deserialize group secret material
    // // ps::GroupSecretMaterial gsm;
    // // placeholder: actual deserialization code
    // // v.recieve_group_secret_material(gsm);
    // v.receive_group_secret_material_serialized(enc_gm_ser);
    // std::cout << "Vehicle received group secret material." << std::endl;
   
    // // std::cin >> n;
    // // Vehicle connects to edge and requests re-encrypted ciphertext
    // std::vector<uint8_t> reenc_ct_ser; // placeholder: actual code to receive from edge
    // // For demo, we can read from file or assume reenc_ct_ser is set
    // ok=get_reenc_ct_from_edge(reenc_ct_ser);
    // if(!ok)
    // {
    //     std::cerr << "Vehicle failed to receive re-encrypted ciphertext from Edge." << std::endl;
    //     return -1;
    // }
    // std::vector<uint8_t> out_message;
    // ok = v.unsigncrypt(reenc_ct_ser, out_message);
    // if(ok)
    // {
    //     std::string recovered_msg(out_message.begin(), out_message.end());
    //     std::cout << "Vehicle successfully unsigncrypted the message: " << recovered_msg << std::endl;
    // }
    // else
    // {
    //     std::cout << "Vehicle failed to unsigncrypt the message." << std::endl;
    // }

    // bool ok = v.unsigncrypt(reenc_ct_ser);
    // if (ok) {
    // std::cout << "Vehicle received re-encrypted ciphertext from Edge." << std::endl;

    return 0;
}