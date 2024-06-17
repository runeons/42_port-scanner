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
# include "../libft/includes/libft.h"
# include <pcap.h>
# include <ft_nmap_enums.h>
# include <ft_nmap_structs.h>
# include <utils_options.h>
# include <utils_colors.h>
# include <assert.h>
# include <pthread.h>

// display.c
void            display_nmap_init(t_data *dt);
void            display_host_init(t_host *host, int no_dns);
void            display_conclusions(t_data *dt);
void            display_nmap_end(t_data *dt, int hosts_nb);

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
void            exit_error_free(const char *msg, ...);
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
char            *reason_string(e_response response);
char            *conclusion_string(e_conclusion conclusion);

// utils_time.c

double          deltaT(struct timeval *t1p, struct timeval *t2p);

// moving_average.c

void            add_value(t_mavg *ma, double value);
double          get_moving_average(t_mavg *ma);

#endif
