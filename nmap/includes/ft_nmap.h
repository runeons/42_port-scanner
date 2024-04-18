#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
// # include <signal.h>
// # include <sys/time.h>
// # include <sys/socket.h>
# include <arpa/inet.h>         // inet_ntoa
# include <netdb.h>             // addrinfo
# include <sys/poll.h>
# include <errno.h>
# include <netinet/ip_icmp.h>   // struct icmphdr
// # include <netinet/udp.h>       // struct udphdr
# include <utils_colors.h>
# include <utils_options.h>
# include <libft.h>
# include <pcap.h>
# include <pthread.h>

// GENERAL
# define TRUE                   1
# define FALSE                  0
# define MAX_SCANS              6
# define MAX_PORTS              1024
# define MAX_SEND               3
# define SCAN_CHARS             "SAUFNXI"
# define SOCKETS_NB             1               // tmp - 1 for now
# define MAX_HOSTNAME_LEN       128
// DEBUG && VERBOSE
# define DEBUG_PARSING          0
# define DEBUG_STRUCT           1
# define DEBUG_NET              0
# define DEBUG_QUEUE            0
# define VERBOSE_THREAD         0
// DEFAULTS OPTIONS VALUES
# define THREADS_NB             4
# define FIRST_PORT             1
# define LAST_PORT              1024
# define MIN_PORT               1
# define MAX_PORT               65535
# define MAX_PORT_RANGE         1024
// POLL
# define NFDS                   1               // tmp - 1 for now
# define POLL_TIMEOUT           5 * 60 * 1000   // 5 minutes
// PCAP
# define PROMISCUOUS            1
// PACKETS SIZES
# define ETH_H_LEN              14
# define IP_H_LEN               20              // sizeof(struct iphdr)
# define ICMP_H_LEN             8               // sizeof(struct icmphdr)
# define ICMP_P_LEN             56
// PACKET FLAGS
# define ICMP_ECHO_REPLY        0               // tmp - initial test only

extern t_lst    *g_queue;                // global queue
extern int      g_scan_types_nb;         // unique scans nb
extern int      g_scans_tracker;         // counter to track & end server
extern int      g_socket;                // main socket
extern int      g_sequence;              // not sure yet whether we need id to send icmp sequence
extern int      g_task_id;               // not sure yet whether we need id to track tasks 
extern int      g_retrieve;              // tmp (count retrieved packets)
extern int      g_sent;                  // tmp (count sent packets)
extern int      g_queued;                // tmp (count queued packets)
extern int      g_verbose;               // tmp (verbose -v)

typedef enum
{
    T_SEND,
    T_RECV,
    T_EMPTY,
}       e_task_type;

typedef enum
{
    ICMP,           // tmp - initial test only
    SYN,
    ACK,
    UDP,
    FIN,
    NUL,
    XMAS,
    UNKNOWN,        // tmp - may not use it
}       e_scan_type;

typedef enum
{
    IN_PROGRESS,
    TCP_SYN_ACK,
    TCP_RST,
    UDP_ANY,
    ICMP_UNR_C_3,       // type 3 unreachablee | code 3
    ICMP_UNR_C_NOT_3,   // type 3 unreachablee | code 1, 2, 9, 10, 13
    NO_RESPONSE,
    OTHER,                  // tmp - may not use it
    ICMP_ECHO_OK,           // tmp - initial test only
}       e_response;

typedef enum
{
    NOT_CONCLUDED,
    OPEN,
    CLOSED,
    FILTERED,
    OPEN_FILTERED,
    UNFILTERED,             // tmp - may not use it
}       e_conclusion;

typedef struct  s_packet
{
	struct icmphdr      h;
	char                payload[ICMP_P_LEN];
}               t_packet;

typedef struct  s_task
{
    int                 id;
    int                 task_type;
    int                 scan_type;
    // T_SEND
    struct sockaddr_in  target_address;
    int                 dst_port;
    // T_RECV
    u_char              *args;
    struct pcap_pkthdr *header;
    u_char        *packet;
}               t_task;

typedef struct  s_scan
{
    e_scan_type         scan_type;
    e_response          response;
    e_conclusion        conclusion;
}               t_scan;

typedef struct s_scan_tracker
{
    t_scan              scan;
    int                 count_sent;
    int                 max_send;
}              t_scan_tracker;

typedef struct  s_port
{
    struct sockaddr_in  target_address;
    int                 port_id;
    int                 conclusion;
    t_scan_tracker      *scan_trackers;
}               t_port;

typedef struct  s_host
{
    char                *input_dest;
    char                *resolved_address;
    char                *resolved_hostname;
    struct sockaddr_in  target_address;
    int                 dst_port;
    t_lst               *ports;
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
    int                 socket;
    struct sockaddr_in  src_address;
    int                 src_port;
    struct pollfd       fds[SOCKETS_NB];
    // SCANS
    t_lst               *queue;
    t_host              host;               // one for now
    t_sniffer           sniffer;
    // OPTIONS
    t_lst               *act_options;
    int                 threads;
    int                 verbose;
    int                 first_port;
    int                 last_port;
    e_scan_type         unique_scans[MAX_SCANS];
}				t_data;

//  options.c
void            init_options_params(t_data *dt);
//  socket.c
void            bind_socket_to_src_port(t_data *dt, int src_port);
void            init_socket(t_data *dt);

// packet.c
void            craft_and_send_icmp(int socket, t_packet *packet, t_task *task);

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
void            debug_queue(t_data dt);
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
void            packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void            sniff_packets(pcap_t *handle, t_data *dt);

// init_data.c
void            fill_host(t_data *dt, char *curr_arg);
void            init_data(t_data *dt, t_parsed_cmd *parsed_cmd);

// tasks.c
void            enqueue_task(t_task *task);
t_task          *dequeue_task();
t_task          *fill_send_task(t_task *task, struct sockaddr_in target_address, int dst_port, e_scan_type scan_type);
t_task          *create_task();
void            init_queue(t_host *host);

// utils_enum.c

char            *task_type_string(e_task_type task_type);
char            *scan_type_string(e_scan_type scan_type);
char            *response_string(e_response response);
char            *conclusion_string(e_conclusion conclusion);


#endif
