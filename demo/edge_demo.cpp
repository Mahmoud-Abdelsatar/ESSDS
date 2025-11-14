#include<iostream>
#include <sstream>
#include <iomanip>
#include "edge.hpp"
#include "socketmanager.hpp"
using namespace ps;

bool receive_reenc_key_from_sp(std::vector<uint8_t>& rk_ser) {
    // Placeholder: actual network code to receive rk_ser from SP
    std::cout << "Receiving re-encryption key from SP." << std::endl;
    // e.g., open TCP connection, receive data, close connection
    int srcok=SocketManager::createServer(5000);
    int client=SocketManager::acceptClient(srcok);
    rk_ser=SocketManager::recvData(client);
    SocketManager::closeSock(client);
    SocketManager::closeSock(srcok);
    return true;
}
bool receive_ct_from_sp(std::vector<uint8_t>& ct_ser, Edge edge, std::vector<uint8_t>& reenc_ct) {
    // Placeholder: actual network code to receive ct_ser from SP
    std::cout << "Receiving ciphertext from SP." << std::endl;
    // e.g., open TCP connection, receive data, close connection
    int srcok=SocketManager::createServer(5000);
    int client=SocketManager::acceptClient(srcok);
    ct_ser=SocketManager::recvData(client);
    std::cout << "Edge received ciphertext from SP." << std::endl;
    reenc_ct = edge.receive_reencrypted_ct(ct_ser);
    std::cout << "Edge re-encrypted ciphertext, size = " << reenc_ct.size() << " bytes." << std::endl;  
     std::vector<uint8_t> msg;
    msg.insert(msg.end(), {'A','C','K'});
    SocketManager::sendData(client, msg);
    SocketManager::closeSock(client);
    SocketManager::closeSock(srcok);
    return true;
}
bool send_reenc_ct_to_vehicle(const std::vector<uint8_t>& reenc_ct) {
    // Placeholder: actual network code to send reenc_ct to Vehicle
    std::cout << "Sending re-encrypted ciphertext to Vehicle, size = " << reenc_ct.size() << " bytes." << std::endl;
    // e.g., open TCP connection, send data, close connection
    int srcok=SocketManager::createServer(5000);
    int client=SocketManager::acceptClient(srcok);
    std::vector<uint8_t> request=SocketManager::recvData(client); // receive request
    SocketManager::sendData(client, reenc_ct);
    SocketManager::closeSock(client);
    SocketManager::closeSock(srcok);
    return true;
}
bool import_sp_public_key(std::vector<uint8_t> &spparams_ser)
{
     std::cout << "Receiving the public key from SP" << std::endl;
    // e.g., open TCP connection, receive data, close connection
    int sock=SocketManager::connectTo("127.0.0.1",5001);
    // set string message "Request Re-encrypted CT" in vector variable.
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), {'R','e','q','u','e','s','t'});
    SocketManager::sendData(sock, msg);
    spparams_ser=SocketManager::recvData(sock);
    // spp.import_serialized(spparams_ser);
    SocketManager::closeSock(sock);
    //     
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
    ep2_t g2; ep2_null();ep2_new(); ep2_curve_get_gen(g2);
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
    Edge edge;
    print_relic_curves_paramters();
    ps::SPPublicParams spp;
    // try
    // {
    //     spp.import_from_file("sp_params.dat");
    // }
    // catch(const std::exception& e)
    // {
    //     std::cerr << e.what() << '\n';
    //     return -1;
    // }
    
    // edge.setSPParams(spp);
    std::cout << "Edge initialized and set SP parameters." << std::endl;
    int n=0;
    std::vector<uint8_t> reenc_ct;
    do
    {
        std::cout<<"Please select one of the following optopns:"<<std::endl;
        std::cout<<"1- Import the SP public key"<<std::endl;
        std::cout<<"2- Receive Re-encryption Key from SP"<<std::endl;
        std::cout<<"3- Receive Ciphertext from SP"<<std::endl;
        std::cout<<"4- Send Re-encrypted Ciphertext for Vehicle"<<std::endl;
        std::cout<<"5- (Benchmarked) Receive Ciphertext from SP"<<std::endl;
        std::cout<<"6- (Benchmarked) Send Re-encrypted Ciphertext for Vehicle"<<std::endl;
        
        std::cout<<"-1- Exit"<<std::endl;
        std::cin >> n;
        if(n==1)
        {
            std::vector<uint8_t> spparams_ser;
            bool ok=import_sp_public_key(spparams_ser);
            if(!ok)
            {
                std::cerr << "Vehicle failed to receive the public key from SP." << std::endl;
                return -1;
            }
            spp.import_serialized(spparams_ser);
            edge.setSPParams(spp);
        }
        else if(n==2){
            // Edge receives reenc key  
            std::vector<uint8_t> rk_ser; // Placeholder: actual code to receive rk_ser from network
            // For demo, we can read from file or assume rk_ser is set
            receive_reenc_key_from_sp(rk_ser);
            bool ok = edge.accept_reenc_key(rk_ser, 1);
            std::cout << "Edge accepted reenc? " << ok << std::endl;
        }
        else if(n==3){
            // Edge receives ciphertext from SP
            std::vector<uint8_t> ct_ser; // Placeholder: actual code to receive ct_ser from network
            // For demo, we can read from file or assume ct_ser is set
            receive_ct_from_sp(ct_ser, edge, reenc_ct);
            
        }
        else if(n==4){
            // Edge send re-encrypted CT to Vehicle
            // Placeholder: actual network code to send reenc_ct to Vehicle
            std::cout << "Edge sent re-encrypted ciphertext to Vehicle." << std::endl;
            send_reenc_ct_to_vehicle(reenc_ct);
        }
        else if(n==5){
            // Edge receives ciphertext from SP
            std::vector<uint8_t> ct_ser; // Placeholder: actual code to receive ct_ser from network
            // For demo, we can read from file or assume ct_ser is set
            for(int i=0;i<100000;i++)
                receive_ct_from_sp(ct_ser, edge, reenc_ct);
            
        }
        else if(n==6){
            // Edge send re-encrypted CT to Vehicle
            // Placeholder: actual network code to send reenc_ct to Vehicle
            std::cout << "Edge sent re-encrypted ciphertext to Vehicle." << std::endl;
            for(int i=0;i<100000;i++)
                send_reenc_ct_to_vehicle(reenc_ct);
        }
    } while (n!=-1 );
    
    // // Edge waits to receive re-encryption key from SP
    // std::vector<uint8_t> rk_ser; // Placeholder: actual code to receive rk_ser from network
    // // For demo, we can read from file or assume rk_ser is set
    // receive_reenc_key_from_sp(rk_ser);
    // bool ok = edge.accept_reenc_key(rk_ser, 1);
    // std::cout << "Edge accepted reenc? " << ok << std::endl;
    // // Edge waits to receive ciphertext from SP
    // std::vector<uint8_t> ct_ser; // Placeholder: actual code to receive ct_ser from network
    // // For demo, we can read from file or assume ct_ser is set
    // receive_ct_from_sp(ct_ser);
    // std::cout << "Edge received ciphertext from SP." << std::endl;
    // auto reenc_ct = edge.receive_reencrypted_ct(ct_ser);
    // std::cout << "Edge re-encrypted ciphertext, size = " << reenc_ct.size() << " bytes." << std::endl;  

    // // Edge wait for Vehicle to connect and send re-encrypted CT
    // // Placeholder: actual network code to send reenc_ct to Vehicle
    // std::cout << "Edge sent re-encrypted ciphertext to Vehicle." << std::endl;
    // send_reenc_ct_to_vehicle(reenc_ct);
    return 0;
}