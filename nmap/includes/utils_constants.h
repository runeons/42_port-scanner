#ifndef UTILS_CONSTANTS_H
# define UTILS_CONSTANTS_H

// GENERAL
# define TRUE                   1
# define FALSE                  0
# define MAX_SCANS              7
# define MAX_PORTS              1024
# define MAX_SEND               3
# define SCAN_CHARS             "SAUFNXI"       // I = tmp (initial test only)
# define SOCKETS_NB             1               // tmp - 1 for now
# define MAX_HOSTNAME_LEN       128
# define MAX_RESULTS_LEN        128
// DEBUG && VERBOSE
# define DEBUG_PARSING          0
# define DEBUG_STRUCT           0
# define DEBUG_NET              0
# define DEBUG_QUEUE            0
# define VERBOSE_THREAD         0
// DEFAULTS OPTIONS VALUES
# define THREADS_NB             1
# define FIRST_PORT             1
# define LAST_PORT              1024
# define MIN_PORT               1
# define MAX_PORT               65535
# define MAX_PORT_RANGE         1024
// POLL
# define SOCKET_POOL_SIZE       10
# define NFDS                   3 * SOCKET_POOL_SIZE
# define POLL_TIMEOUT           5 * 60 * 1000   // 5 minutes
// PCAP
# define PROMISCUOUS            1
// PACKETS SIZES
# define ETH_H_LEN              14
# define IP_H_LEN               20              // sizeof(struct iphdr)
# define ICMP_H_LEN             8               // sizeof(struct icmphdr)
# define ICMP_P_LEN             56
# define TCP_P_LEN              4
# define UDP_P_LEN              29              //based on nmap
// PACKET FLAGS
# define ICMP_ECHO_REPLY        0               // tmp (initial test only)
// WINDOW
#define WINDOW_SIZE 5

#endif
