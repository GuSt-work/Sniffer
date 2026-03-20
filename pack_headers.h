#ifndef PACK_HEADERS_H
#define PACK_HEADERS_H

#pragma once
#pragma pack(push, 1)

struct IPHeader {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short flags_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_ip;
    unsigned int dst_ip;
};

#pragma pack(pop)



#endif // PACK_HEADERS_H
