#ifndef FT_NMAP_STRUCTS_H
# define FT_NMAP_STRUCTS_H

# include <utils_constants.h>

extern t_lst    *g_queue;                // global queue
extern int      g_scan_types_nb;         // unique scans nb
extern int      g_scan_tracker_id;       // unique id (to track tasks responses)
extern int      g_remaining_scans;       // counter to track & end server

extern int      g_sequence;              // not sure yet whether we really need it
extern int      g_retrieved;             // tmp (count retrieved packets)
extern int      g_sent;                  // tmp (count sent packets)
extern int      g_queued;                // tmp (count queued packets)
extern int      g_verbose;               // tmp (verbose -v)

struct icmp_packet
{
    struct icmphdr      h;
	char                payload[ICMP_P_LEN];
};

struct tcp_packet
{
    struct tcphdr       h;
	char                payload[TCP_P_LEN];
};

struct udp_packet
{
    struct udphdr       h;
    char                payload[UDP_P_LEN];
};

typedef union
{
    void                *generic;
    struct icmp_packet  icmp;
    struct tcp_packet   tcp;
    struct udp_packet   udp;
}       u_packet;

typedef struct
{
    e_packet_type   type;
    u_packet        packet;
    size_t          size;
}               t_packet;

typedef struct  s_task //if there is a clear distinction between the T_SEND and T_RECV fields then turn them into a union
{
    int                 scan_tracker_id;
    int                 task_type;
    uint16_t            src_port;
    // T_SEND
    int                 scan_type;
    struct sockaddr_in  target_address;
    int                 dst_port;
    int                 socket;
    int                 src_ip;
    // T_RECV
    u_char              *args;
    struct pcap_pkthdr  *header;
    u_char              *packet;
}               t_task;

typedef struct  s_scan
{
    e_scan_type         scan_type;
    e_response          response;
    e_conclusion        conclusion;
}               t_scan;

typedef struct  s_scan_tracker
{
    int                 id;
    t_scan              scan;
    int                 count_sent;
    int                 max_send;
    uint16_t            dst_port;
    uint16_t            src_port;
    struct timeval      last_send;

}               t_scan_tracker;

typedef struct  s_port
{
    int                 port_id;
    e_conclusion        conclusion_tcp;
    e_conclusion        conclusion_udp;
    t_scan_tracker      *scan_trackers;
    e_response          tcp_reason;
    e_response          udp_reason;
}               t_port;

typedef struct  s_moving_average
{
    double              values[WINDOW_SIZE];
    int                 index;
    int                 count;
    double              sum;
}               t_mavg;


typedef struct  s_host
{
    char                *input_dest;
    char                *resolved_address;
    char                *resolved_hostname;
    int                 dst_port;
    int                 approx_rtt_upper_bound;
    t_lst               *ports;
    struct sockaddr_in  target_address;
    t_mavg              ma;
}               t_host;

typedef struct  s_sniffer
{
    pcap_t              *handle;
    char                *device;
    char                *filter;
}               t_sniffer;

typedef struct  s_data
{
    // SOCKET
    int                 icmp_socket_pool[SOCKET_POOL_SIZE];
    int                 udp_socket_pool[SOCKET_POOL_SIZE];
    int                 tcp_socket_pool[SOCKET_POOL_SIZE];
    struct sockaddr_in  src_address;
    int                 src_port;
    int                 src_ip;
    struct pollfd       fds[NFDS];
    // SCANS
    t_lst               *queue;
    t_host              host;               // one for now
    t_sniffer           sniffer;
    // OPTIONS
    t_lst               *act_options;
    int                 threads;
    int                 verbose;
    int                 no_dns;
    int                 reason;
    uint16_t            *first_port;
    uint16_t            *last_port;
    uint16_t            arg_ports[1024];
    int                 n_ports;
    e_scan_type         unique_scans[MAX_SCANS];
    FILE                *file;
    int                 max_retries;
    // STATS
    struct timeval      tz;
    struct timeval      init_tv;
    int                 hosts_nb;
}				t_data;

#endif
