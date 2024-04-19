#include "ft_nmap.h"

void    init_handle(t_sniffer *sniffer)
{
    pcap_if_t           *interfaces;
    struct bpf_program  compiled_filter;
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h
    bpf_u_int32         dev_mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net_mask;		                    // The IP of our sniffing device   

    if (pcap_lookupnet(sniffer->device, &net_mask, &dev_mask, err_buf) == -1) // get network mask needed for the filter
    {
        warning_str("No network mask for device:", sniffer->device);
        net_mask = 0;
        dev_mask = 0;
    }
    debug_net_mask(net_mask, dev_mask);
    if (pcap_findalldevs(&interfaces, err_buf) == -1)
        exit_error_str("Finding devices", err_buf);
    debug_interfaces(interfaces);
    if ((sniffer->handle = pcap_open_live(sniffer->device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
        exit_error_str("Opening device:", err_buf);
    if (pcap_compile(sniffer->handle, &compiled_filter, sniffer->filter, 0, net_mask) == -1)
        exit_error_str("Parsing filter:", pcap_geterr(sniffer->handle));
    if (pcap_setfilter(sniffer->handle, &compiled_filter) == -1)
        exit_error_str("Compiling filter:", pcap_geterr(sniffer->handle));
    pcap_freealldevs(interfaces);
    pcap_freecode(&compiled_filter);
}

void    init_sniffer(t_sniffer *sniffer, char *device, char *filter)
{
    if (!(sniffer->device = ft_strdup(device)))
        exit_error("Malloc failure.");
    if (!(sniffer->filter = ft_strdup(filter)))
        exit_error("Malloc failure.");
}

void    packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
{
    t_task  *task = create_task(g_socket);

    task->scan_tracker_id   = 100000 + g_retrieve++; // TO DO
    task->task_type         = T_RECV;
    task->args              = args;
    task->header            = (struct pcap_pkthdr *)header;
    task->packet            = (u_char *)packet;
    enqueue_task(task);
    // debug_task(*task);
}

void    sniff_packets(pcap_t *handle, t_data *dt)
{
    (void)dt;
    printf(C_G_BLUE"[INFO]"C_RES"     Ready to sniff...\n");
    while (g_remaining_scans != 0)
        pcap_dispatch(handle, 0, packet_handler, 0);
    debug_queue(*dt);
    // printf(C_G_BLUE"[INFO]"C_RES"     Capture completed\n");
}
