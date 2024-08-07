#include "../includes/ft_nmap.h"

extern pthread_mutex_t mutex;

t_scan all_scans[] =
{
    {SYN,   TCP_SYN_ACK,         OPEN          },
    {SYN,   TCP_RST,             CLOSED        },
    {SYN,   NO_RESPONSE,         FILTERED      },
    {SYN,   ICMP_UNR_C_3,        FILTERED      },
    {SYN,   ICMP_UNR_C_NOT_3,    FILTERED      },

    {ACK,   TCP_RST,             UNFILTERED    },
    {ACK,   NO_RESPONSE,         FILTERED      },
    {ACK,   ICMP_UNR_C_3,        FILTERED      },
    {ACK,   ICMP_UNR_C_NOT_3,    FILTERED      },

    {UDP,   UDP_ANY,             OPEN          },
    {UDP,   NO_RESPONSE,         OPEN_FILTERED },
    {UDP,   ICMP_UNR_C_3,        CLOSED        },
    {UDP,   ICMP_UNR_C_NOT_3,    FILTERED      },

    {FIN,   NO_RESPONSE,         OPEN_FILTERED },
    {FIN,   TCP_RST,             CLOSED        },
    {FIN,   ICMP_UNR_C_3,        FILTERED      },
    {FIN,   ICMP_UNR_C_NOT_3,    FILTERED      },

    {NUL,   NO_RESPONSE,         OPEN_FILTERED },
    {NUL,   TCP_RST,             CLOSED        },
    {NUL,   ICMP_UNR_C_3,        FILTERED      },
    {NUL,   ICMP_UNR_C_NOT_3,    FILTERED      },

    {XMAS,  NO_RESPONSE,         OPEN_FILTERED },
    {XMAS,  TCP_RST,             CLOSED        },
    {XMAS,  ICMP_UNR_C_3,        FILTERED      },
    {XMAS,  ICMP_UNR_C_NOT_3,    FILTERED      },
};

e_conclusion get_scan_conclusion(uint8_t target_is_localhost, e_scan_type scan_type, e_response response)
{
    (void) target_is_localhost;
    for (size_t i = 0; i < sizeof(all_scans) / sizeof(all_scans[0]); i++)
    {
        if (all_scans[i].scan_type == scan_type && all_scans[i].response == response)
            return (all_scans[i].conclusion);
    }
    // important_warning("cannot conclude scan result from response.\n");
    return NOT_CONCLUDED;
}


static t_scan_tracker *find_tracker_with_id(t_data *dt, int tracker_id, uint16_t dst_port)
{
    t_lst *curr_port = dt->host.ports;
    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        if (port == NULL)
            exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
        if (port->port_id != dst_port)
            goto next_port;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]); //change scan_trackers to be constant size and we can easily access the correct index based on the scan type
            if (tracker == NULL)
                exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
            if (tracker->id == tracker_id)
                return tracker;
        }
        next_port:
        curr_port = curr_port->next;
    }
    return NULL;
}


static t_scan_tracker *find_tracker_from_ports(t_data *dt, uint16_t src_port, uint16_t dst_port)
{
    t_lst *curr_port = dt->host.ports;
    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        if (port == NULL)
            exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
        if (port->port_id != dst_port)
            goto next_port;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]); //change scan_trackers to be constant size and we can easily access the correct index based on the scan type
            if (tracker == NULL)
                exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
            if (tracker->src_port == src_port)
                return tracker;
        }
        next_port:
        curr_port = curr_port->next;
    }
    return NULL;
}

e_response determine_response_type(t_data *dt, t_task *task)
{
    (void)dt;
    if (task == NULL || task->header == NULL)
        return OTHER;
    if (!task->header->len || (task->header->len < ETH_H_LEN + IP_H_LEN))
    {
        // important_warning("TASK is TOO SMALL to contain IP HEADER - return OTHER\n");
        return OTHER;
    }
    struct ip *ip_hdr = (struct ip *)(task->packet + ETH_H_LEN);
    if (ip_hdr->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + IP_H_LEN);

        if (tcp_hdr->syn && tcp_hdr->ack)
            return TCP_SYN_ACK;
        else if (tcp_hdr->rst)
            return TCP_RST;
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP)
        return UDP_ANY;
    else if (ip_hdr->ip_p == IPPROTO_ICMP)
    {
        struct icmp *icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + IP_H_LEN);

        if (icmp_hdr->icmp_type == ICMP_ECHOREPLY)
            return ICMP_ECHO_OK;
        else if (icmp_hdr->icmp_type == ICMP_UNREACH)
        {
            if (icmp_hdr->icmp_code == 3)
            {
                if (ip_hdr->ip_src.s_addr != dt->host.target_address.sin_addr.s_addr)
                    return ICMP_UNR_C_NOT_3;
                return ICMP_UNR_C_3;
            }
            else if (icmp_hdr->icmp_code == 1 || icmp_hdr->icmp_code == 2 ||
                     icmp_hdr->icmp_code == 9 || icmp_hdr->icmp_code == 10 ||
                     icmp_hdr->icmp_code == 13)
                return ICMP_UNR_C_NOT_3;
        }
    }
    return OTHER;
}

void    update_port_conclusion(t_port *port, t_scan_tracker *tracker)
{

    if (tracker->scan.scan_type == UDP)
    {
        if (port->conclusion_udp < tracker->scan.conclusion)
        {
            port->conclusion_udp = tracker->scan.conclusion;
            port->udp_reason = tracker->scan.response;                    
        }
    }
    else
    {
        if (port->conclusion_tcp < tracker->scan.conclusion)
        {
            port->conclusion_tcp = tracker->scan.conclusion;                    
            port->tcp_reason = tracker->scan.response;                    
        }
    }
}

void    update_scan_tracker(t_data *dt, int scan_tracker_id, e_response response)
{
    t_lst *curr_port = dt->host.ports;
    struct timeval recv_time;

    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        if (port == NULL)
            exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL)
                exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
            if (tracker->id == scan_tracker_id)
            {
                tracker->scan.response = response;
                tracker->scan.conclusion = get_scan_conclusion(dt->target_is_localhost, tracker->scan.scan_type, response);
                update_port_conclusion(port, tracker);
                decr_remaining_scans(1);

                gettimeofday(&recv_time, NULL);
                add_value(&dt->host.ma, deltaT(&tracker->last_send, &recv_time));
                return;
            }
        }
        curr_port = curr_port->next;
    }
    // important_warning("scan_tracker_id not found.\n");
}

int     extract_response_id(t_data *dt, t_task *task, e_response response)
{   
    int id = -1;
    struct icmp     *icmp_hdr = NULL;
    struct tcphdr   *tcp_hdr  = NULL;
    struct udphdr   *udp_hdr  = NULL;
    struct ip       *inner_ip_hdr = NULL;

    switch (response)
    {
        case ICMP_ECHO_OK:
        {
            icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + sizeof(struct ip));
            if (icmp_hdr)
                id = icmp_hdr->icmp_id;
            break;            
        }
        case ICMP_UNR_C_NOT_3: case ICMP_UNR_C_3: // Assuming this constant represents ICMP errors
        {
            icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + sizeof(struct ip));
            if (icmp_hdr)
            {
                inner_ip_hdr = (struct ip *)((char *)icmp_hdr + 8);
                if (inner_ip_hdr->ip_dst.s_addr != dt->host.target_address.sin_addr.s_addr)
                    return -1;
                if (inner_ip_hdr->ip_p == IPPROTO_TCP) {
                    // TCP Protocol
                    tcp_hdr = (struct tcphdr *)((u_char *)inner_ip_hdr + (inner_ip_hdr->ip_hl * 4));
                    int src_port = ntohs(tcp_hdr->source);
                    int dst_port = ntohs(tcp_hdr->dest);
                    t_scan_tracker *tracker = find_tracker_from_ports(dt, src_port, dst_port); 
                    if (tracker)
                        id = tracker->id;
                } else if (inner_ip_hdr->ip_p == IPPROTO_UDP) {
                    // UDP Protocol
                    udp_hdr = (struct udphdr *)((u_char *)inner_ip_hdr + (inner_ip_hdr->ip_hl * 4));
                    int src_port = ntohs(udp_hdr->uh_sport);
                    int dst_port = ntohs(udp_hdr->uh_dport);
                    t_scan_tracker *tracker = find_tracker_from_ports(dt, src_port, dst_port); 
                    if (tracker)
                        id = tracker->id;
                } else {
                    printf("Unsupported encapsulated transport layer protocol: %d\n", inner_ip_hdr->ip_p);
                }
            }
            break;
        }
        case TCP_SYN_ACK: case TCP_RST:
        {
            tcp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + sizeof(struct ip));
            if (tcp_hdr)
            {
                t_scan_tracker *tracker = find_tracker_from_ports(dt, htons(tcp_hdr->dest), htons(tcp_hdr->source)); //identification is based on our source port
                if (tracker)
                    id = tracker->id;
            }
            break;
        }
        case UDP_ANY:
        {
            udp_hdr = (struct udphdr *)(task->packet + ETH_H_LEN + sizeof(struct ip));
                if (udp_hdr)
                {
                    t_scan_tracker *tracker =  find_tracker_from_ports(dt, htons(udp_hdr->dest), htons(udp_hdr->source));
                    if (tracker)
                        id = tracker->id;
                }
            break;
        }
        default:
            break;
    }
    return id;
}

void    handle_recv_task(t_data *dt, t_task *task)
{
    e_response      response = OTHER;

    response = determine_response_type(dt, task);
    if (response == OTHER)
        return ;
    task->scan_tracker_id = extract_response_id(dt, task, response);
    update_scan_tracker(dt, task->scan_tracker_id, response);
}

void    handle_send_task(t_data *dt, t_task *task)
{
    for (int i = 0; i < NFDS; i++)
    {
        if (dt->fds[i].fd == task->socket)
        {
            if (dt->fds[i].revents == 0)
            {
                enqueue_task(task);
                // warning("[REQUEUED] scan %d: No event detected for this socket.\n", task->scan_tracker_id);
                continue;
            }
            if (!(dt->fds[i].revents & POLLOUT))
                exit_error_full_free(dt, "Poll unexpected result\n");

            t_packet packet;

            switch (task->scan_type)
            {
                case SYN:
                case ACK:
                case FIN:
                case NUL:
                case XMAS:
                    construct_tcp_packet(&packet, task);
                    break;
                case UDP:
                    construct_udp_packet(&packet, task);
                    break;
                default:
                    // warning("Unknown SCAN.\n");
                    continue;
            }
            send_packet(task->socket, &packet, &task->target_address, task->scan_tracker_id);
            t_scan_tracker *this_scan_tracker = find_tracker_with_id(dt, task->scan_tracker_id,task->dst_port);
            if (!this_scan_tracker)
                continue;
            gettimeofday(&this_scan_tracker->last_send, NULL);
            this_scan_tracker->count_sent++;
        }
    }
}

void        handle_never_received(uint8_t target_is_localhost, t_port *port, t_scan_tracker *tracker)
{
    tracker->scan.response = NO_RESPONSE;
    debug_scan(tracker->scan);
    tracker->scan.conclusion = get_scan_conclusion(target_is_localhost, tracker->scan.scan_type, tracker->scan.response);
    update_port_conclusion(port, tracker);
}

static void handle_check_task(t_data *dt, t_task *task)
{
    (void) task;
    int tmp_socket = -1;
    int n_done = 0;
    struct timeval      time_now = {0,0};
    int  sock_index = 0;
    gettimeofday(&time_now, NULL);

    t_lst *curr_port = dt->host.ports;
    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        if (port == NULL)
            exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
        for (int i = 0; i < g_scan_types_nb; i++, sock_index++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL)
                exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
            
            if (tracker->scan.conclusion == NOT_CONCLUDED)
            {
                if (tracker->count_sent > 0 && tracker->count_sent < tracker->max_retries)
                {
                    if (deltaT(&tracker->last_send ,&time_now) > (get_moving_average(&dt->host.ma) > 0 ? get_moving_average(&dt->host.ma):5000))
                    {
                        t_task  *send_task = create_task();
                        tmp_socket = select_socket_from_pool(dt, tracker->scan.scan_type, sock_index);
                        fill_send_task(send_task, tracker->id, dt->host.target_address, port->port_id, tracker->scan.scan_type, tmp_socket, dt->src_ip, tracker->dst_port);
                        enqueue_task(send_task);
                    }
                }
                else
                {
                    handle_never_received(dt->target_is_localhost, port, tracker);
                    n_done++;
                }
            }
        }
        curr_port = curr_port->next;
    }
    if (n_done > 0)
        decr_remaining_scans(n_done);
    alarm(1);
}

void    handle_task(t_data *dt, t_task *task)
{
    if (task->task_type == T_SEND)
        handle_send_task(dt, task);
    else if (task->task_type == T_RECV)
        handle_recv_task(dt, task);
    else if (task->task_type == T_CHECK)
        handle_check_task(dt, task);
}
