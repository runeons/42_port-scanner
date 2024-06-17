#ifndef FT_NMAP_ENUMS_H
# define FT_NMAP_ENUMS_H

# define packet(x) packet.x

typedef enum
{
    T_SEND,
    T_RECV,
    T_CHECK,
    T_EMPTY,
}       e_task_type;

typedef enum
{
    ICMP,               // tmp (initial test only)
    SYN,
    ACK,
    UDP,
    FIN,
    NUL,
    XMAS,
    UNKNOWN,            // tmp (may not use it)
}       e_scan_type;

typedef enum
{
    IN_PROGRESS,
    TCP_SYN_ACK,
    TCP_RST,
    UDP_ANY,
    ICMP_UNR_C_3,       // type 3 unreachable | code 3
    ICMP_UNR_C_NOT_3,   // type 3 unreachable | code 1, 2, 9, 10, 13
    NO_RESPONSE,
    OTHER,              // tmp (may not use it)
    ICMP_ECHO_OK,
}       e_response;

typedef enum
{
    NOT_CONCLUDED,
    CLOSED,
    OPEN_FILTERED,
    FILTERED,
    UNFILTERED,
    OPEN,
}       e_conclusion;

typedef enum
{
    PACKET_TYPE_ICMP = ICMP,
    PACKET_TYPE_SYN = SYN,
    PACKET_TYPE_ACK = ACK,
    PACKET_TYPE_UDP = UDP,
    PACKET_TYPE_FIN = FIN,
    PACKET_TYPE_NUL = NUL,
    PACKET_TYPE_XMAS = XMAS,
}       e_packet_type;

enum protocol_pool_index
{
    ICMP_INDEX,
    UDP_INDEX,
    TCP_INDEX
};

#endif
