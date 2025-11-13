#ifndef SOCKET_MANAGER_H
#define SOCKET_MANAGER_H

#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>
#include <iostream>

class SocketManager {
public:
    // create a listening TCP socket on given port, returns server fd
    static int createServer(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) throw std::runtime_error("socket() failed");
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock); throw std::runtime_error("bind() failed");
        }
        if (listen(sock, 5) < 0) {
            close(sock); throw std::runtime_error("listen() failed");
        }
        return sock;
    }

    // accept a single client (blocking)
    static int acceptClient(int serverSock) {
        sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int client = accept(serverSock, (sockaddr*)&cli, &clen);
        if (client < 0) throw std::runtime_error("accept() failed");
        return client;
    }

    // connect to host:port (client)
    static int connectTo(const std::string& host, int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) throw std::runtime_error("socket() failed");
        sockaddr_in serv;
        std::memset(&serv, 0, sizeof(serv));
        serv.sin_family = AF_INET;
        serv.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &serv.sin_addr) <= 0) {
            close(sock); throw std::runtime_error("inet_pton failed");
        }
        if (connect(sock, (sockaddr*)&serv, sizeof(serv)) < 0) {
            close(sock); throw std::runtime_error("connect() failed");
        }
        return sock;
    }

    // send framed data: 4-byte big-endian length + payload
    static void sendData(int sock, const std::vector<unsigned char>& data) {
        uint32_t len = htonl(static_cast<uint32_t>(data.size()));
        if (send_all(sock, (unsigned char*)&len, sizeof(len)) != (ssize_t)sizeof(len))
            throw std::runtime_error("send len failed");
        if (!data.empty()) {
            if (send_all(sock, data.data(), data.size()) != (ssize_t)data.size())
                throw std::runtime_error("send payload failed");
        }
    }

    // receive framed data (blocking)
    static std::vector<unsigned char> recvData(int sock) {
        uint32_t len_net;
        recv_all(sock, (unsigned char*)&len_net, sizeof(len_net));
        uint32_t len = ntohl(len_net);
        std::vector<unsigned char> buf(len);
        if (len) recv_all(sock, buf.data(), len);
        return buf;
    }

    static void closeSock(int sock) {
        if (sock >= 0) close(sock);
    }

private:
    static ssize_t send_all(int sock, const unsigned char* buf, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t s = send(sock, buf + sent, len - sent, 0);
            if (s <= 0) return s;
            sent += s;
        }
        return sent;
    }
    static void recv_all(int sock, unsigned char* buf, size_t len) {
        size_t recvd = 0;
        while (recvd < len) {
            ssize_t r = recv(sock, buf + recvd, len - recvd, MSG_WAITALL);
            if (r <= 0) throw std::runtime_error("recv() failed or connection closed");
            recvd += r;
        }
    }
};

#endif // SOCKET_MANAGER_H
