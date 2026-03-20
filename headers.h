#ifndef HEADERS_H
#define HEADERS_H

#pragma once
#include <winsock2.h>  // для ntohs/ntohl
#include <ws2tcpip.h>  // для inet_ntoa
#include <cstdint>

#pragma pack(push, 1)  // выравнивание 1 байт

// ----------------- IP Header -----------------
struct IPHeader {
    unsigned char ihl:4;       // длина заголовка в 32-бит словах
    unsigned char version:4;   // версия IP
    unsigned char tos;          // type of service
    unsigned short total_length;
    unsigned short id;
    unsigned short flags_offset;
    unsigned char ttl;          // время жизни
    unsigned char protocol;     // протокол (TCP=6, UDP=17)
    unsigned short checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// ----------------- TCP Header -----------------
struct TCPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    uint32_t seq;
    uint32_t ack;
    unsigned char offset_reserved;  // offset (4 бита) + reserved (4 бита)
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent;
};

// ----------------- UDP Header -----------------
struct UDPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short len;
    unsigned short checksum;
};

#pragma pack(pop)

#endif // HEADERS_H

