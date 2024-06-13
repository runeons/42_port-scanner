#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <signal.h>
# include <sys/time.h>
// # include <sys/socket.h>
# include <arpa/inet.h>         // inet_ntoa
# include <netdb.h>             // addrinfo
# include <sys/poll.h>
# include <errno.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
// # include <netinet/udp.h>
# include <netinet/ip_icmp.h>   // struct icmphdr
# include <utils_colors.h>
# include <utils_options.h>
# include "../libft/includes/libft.h"
# include <assert.h>
# include <pcap.h>
# include <pthread.h>

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

extern t_lst    *g_queue;                // global queue
extern int      g_scan_types_nb;         // unique scans nb
extern int      g_scan_tracker_id;       // unique id (to track tasks responses)
extern int      g_remaining_scans;       // counter to track & end server

extern int      g_sequence;              // not sure yet whether we really need it
extern int      g_retrieved;             // tmp (count retrieved packets)
extern int      g_sent;                  // tmp (count sent packets)
extern int      g_queued;                // tmp (count queued packets)
extern int      g_verbose;               // tmp (verbose -v)

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

#define packet(x) packet.x

struct icmp_packet{
    struct icmphdr      h;
	char                payload[ICMP_P_LEN];
};

struct tcp_packet{
    struct tcphdr       h;
	char                payload[TCP_P_LEN];
};

struct udp_packet{
    struct udphdr       h;
    char                payload[UDP_P_LEN];
};

typedef union {
    void                *generic;
    struct icmp_packet  icmp;
    struct tcp_packet   tcp;
    struct udp_packet   udp;
} u_packet;

typedef enum {
    PACKET_TYPE_ICMP = ICMP,
    PACKET_TYPE_SYN = SYN,
    PACKET_TYPE_ACK = ACK,
    PACKET_TYPE_UDP = UDP,
    PACKET_TYPE_FIN = FIN,
    PACKET_TYPE_NUL = NUL,
    PACKET_TYPE_XMAS = XMAS,
} e_packet_type;


typedef struct{
    e_packet_type   type;
    u_packet        packet;
    size_t          size;
} t_packet;

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

typedef struct s_scan_tracker
{
    int                 id;
    t_scan              scan;
    int                 count_sent;
    int                 max_send;
    uint16_t            dst_port;
    uint16_t            src_port;
    struct timeval      last_send;

}              t_scan_tracker;

typedef struct  s_port
{
    int                 port_id;
    e_conclusion        conclusion_tcp;
    e_conclusion        conclusion_udp;
    t_scan_tracker      *scan_trackers;
}               t_port;


#define WINDOW_SIZE 5

typedef struct s_moving_average{
    double values[WINDOW_SIZE];
    int index;
    int count;
    double sum;
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

enum protocol_pool_index{
    ICMP_INDEX,
    UDP_INDEX,
    TCP_INDEX
};

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
    uint16_t            *first_port;
    uint16_t            *last_port;
    uint16_t            arg_ports[1024];
    int                 n_ports;
    e_scan_type         unique_scans[MAX_SCANS];
}				t_data;

// display.c
void            display_nmap_init(t_data *dt);
void            display_host_init(t_host *host);
void            display_conclusions(t_data *dt);

//  options.c
void            init_options_params(t_data *dt);
//  socket.c
//void            bind_socket_to_src_port(t_data *dt, int src_port);
void            init_socket(t_data *dt);
int             select_socket_from_pool(t_data *dt, e_scan_type scan_type, int index);

// packet.c
void            send_packet(int socket, t_packet *packet, struct sockaddr_in *target_address, int task_id);
void            craft_icmp_packet(t_packet *packet, t_task *task);
void            construct_tcp_packet(t_packet *packet, t_task *task);
void            construct_udp_packet(t_packet *packet, t_task *task);

// utils_debug.c
void            debug_icmp_packet(t_packet packet);
void            debug_interfaces(pcap_if_t *interfaces);
void            debug_net_mask(bpf_u_int32 net_mask, bpf_u_int32 dev_mask);
void            debug_addrinfo(struct addrinfo ai);
void            debug_sockaddr_in(struct sockaddr_in addr);
void            debug_task(t_task task);
void            debug_scan_tracker(t_scan_tracker scan_tracker);
void            debug_scan(t_scan scan);
void            debug_port(t_port port);
void            debug_host(t_host host);
void            debug_queue();
void            debug_end(t_data dt);

// utils_print.c
void            print_info(char *msg);
void            print_info_int(char *msg, int n);
void            print_info_task(char *msg, int n);
void            print_info_thread(char *msg);

// utils_error.c
void            exit_error(char *msg);
void            exit_error_str(char *msg, char *error);
void            exit_error_close_socket(char *msg, int socket);
void            warning(char *msg);
void            warning_str(char *msg, char *error);
void            warning_int(char *msg, int nb);

// sniffer.c
void            init_handle(t_sniffer *sniffer);
void            init_sniffer(t_sniffer *sniffer, char *device, char *filter);
pcap_if_t       *find_devices();
void            packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void            sniff_packets(pcap_t *handle, t_data *dt);

// init_data.c
int             fill_host(t_data *dt, char *curr_arg);
void            init_data(t_data *dt, t_parsed_cmd *parsed_cmd);
int             resolve_address(t_host *host);
int             resolve_hostname(t_host *host);
void            init_host(t_host *host);

// tasks_queue.c
void            decr_remaining_scans(int n);
void            enqueue_task(t_task *task);
t_task          *dequeue_task();
t_task          *fill_send_task(t_task *task, int id, struct sockaddr_in target_address, uint16_t dst_port, e_scan_type scan_type, int socket, int src_ip, uint16_t src_port);
t_task          *create_task();
void            init_queue(t_data *dt);

// tasks_handling.c
void            handle_task(t_data *dt, t_task *task);

// utils_enum.c

char            *task_type_string(e_task_type task_type);
char            *scan_type_string(e_scan_type scan_type);
char            *response_string(e_response response);
char            *conclusion_string(e_conclusion conclusion);

// utils_time.c

double          deltaT(struct timeval *t1p, struct timeval *t2p);

// moving_average.c

void            add_value(t_mavg *ma, double value);
double          get_moving_average(t_mavg *ma);

#endif
