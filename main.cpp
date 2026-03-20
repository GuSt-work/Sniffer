#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "headers.h"
#include <fstream>
#include <csignal>

bool running = true;

void signal_handler(int signum) {
    running = false;
}

int main(int argc, char *argv[])
{
    std::signal(SIGINT, signal_handler);


    WSADATA wsa;
    //функция инициализации winsock. Первый параметр - версия библиотеки
    //Второй - структура - содержит информацию о версии Winsock
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){
        std::cout << "WSAStartup failed\n";
        return 1;
    }

    //-------------------------------------
    DWORD bufferLenght;
    WSAEnumProtocols(NULL, NULL, &bufferLenght);

    WSAPROTOCOL_INFO* buffer1 = (WSAPROTOCOL_INFO*)malloc(bufferLenght);

    int count = WSAEnumProtocols(NULL, buffer1, &bufferLenght);
    if (count == SOCKET_ERROR){
        std::cout << "WSAEnumProtocols ошибкуа";
        free(buffer1);
        return 1;
    }
    for (int i = 0; i < count; i++) {
        printf("Protocol: %S\n", buffer1[i].szProtocol);
        printf("Address Family: %d\n", buffer1[i].iAddressFamily);
        printf("Socket Type: %d\n", buffer1[i].iSocketType);
        printf("Protocol ID: %d\n\n", buffer1[i].iProtocol);
    }
    free(buffer1);

    const char* ip_str = argv[1];

    // --- Настраиваем структуру для getaddrinfo ---
    ADDRINFOA hints = {0};
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP (можно 0 для любого)
    hints.ai_flags = AI_NUMERICHOST;    // IP адрес, а не имя хоста

    ADDRINFOA* result = nullptr;

    int res = getaddrinfo(ip_str, nullptr, &hints, &result);
    if(res != 0) {
        std::cout << "getaddrinfo failed: " << gai_strerrorA(res) << std::endl;
        WSACleanup();
        return 1;
    }

    // --- Выводим информацию ---
    for(ADDRINFOA* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        sockaddr_in* addr_in = (sockaddr_in*)ptr->ai_addr;
        std::cout << "IP Address: " << inet_ntoa(addr_in->sin_addr) << std::endl;
    }
    return 0;
    //-------------------------------------

    //1 - семейство адресов протокола
    //2- Тип сокета для данного семейства
    //3 - конкретный транспорт для данного семейства адресов
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if(sock == INVALID_SOCKET){
        std::cout << "socket creation failed\n";
        return 1;
    }


    //Аргумент командной строки
    if(argc < 3){
        std::cout << "Usage: sniffer.exe <IP> <file>\n";
        return 1;
    }

    std::ofstream log(argv[2], std::ios::out);
    if (!log.is_open()) {
        std::cout << "Cannot open file " << argv[2] << "\n";
        return 1;
    }

    //Создаём адрес
    //Полу sin_por задает, какой коммуникационный порт TCP или IP
    //Будет использован для итентификации службы сервера
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    addr.sin_port = 0;

    if(bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR){
        std::cout << "Bind failed\n";
        return 1;
    }

    //Включаем режим сниффера
    DWORD flag = 1;
    if(ioctlsocket(sock, SIO_RCVALL, &flag) != 0){
        std::cout << "ioctlsocket failed\n";
        return 1;
    }

    //Пробуем читать пакеты
    char buffer[65536];

    while(running){
        int size = recv(sock, buffer, sizeof(buffer), 0);

        if(size > 0){
            std::cout << "packet received: " << size << "bytes\n";

            IPHeader* ip = (IPHeader*)buffer;

            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = ip->src_ip;
            dst_addr.s_addr = ip->dst_ip;

            log << "IP Packet: "
                << "Src=" << inet_ntoa(src_addr)
                << " Dst=" << inet_ntoa(dst_addr)
                << " TTL=" << (int)ip->ttl
                << " Protocol=" << (int)ip->protocol
                << " Size=" << size
                << "\n";
            log.flush();

            unsigned short ip_header_len = ip->ihl * 4; // длина заголовка в байтах

            if (ip->protocol == IPPROTO_TCP) {
                TCPHeader* tcp = (TCPHeader*)(buffer + ip_header_len);

                log << " TCP Packet: "
                    << "SrcPort=" << ntohs(tcp->src_port)
                    << " DstPort=" << ntohs(tcp->dst_port)
                    << " Seq=" << ntohl(tcp->seq)
                    << " Ack=" << ntohl(tcp->ack)
                    << "\n";
                log.flush();
            }

            if (ip->protocol == IPPROTO_UDP) {
                UDPHeader* udp = (UDPHeader*)(buffer + ip_header_len);

                log << " UDP Packet: "
                    << "SrcPort=" << ntohs(udp->src_port)
                    << " DstPort=" << ntohs(udp->dst_port)
                    << " Length=" << ntohs(udp->len)
                    << "\n";
                log.flush();
            }
        }
    }


}
