#include "../includes/ft_nmap.h"

// cf. ft_nmap.h for details
t_lst *g_queue         = NULL;
int g_scan_types_nb    = 0;
int g_remaining_scans  = 0;
int g_scan_tracker_id  = 0;
int g_sequence         = 0;
int g_retrieved        = 0;
int g_sent             = 0;
int g_queued           = 0;
int g_verbose          = FALSE;

static int      get_source_numeric_ip(pcap_if_t *interfaces)
{
    pcap_addr_t *addr;

    for (addr = interfaces->addresses; addr != NULL; addr = addr->next)
    {
        if (addr->addr != NULL)
        {
            if (addr->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *sa = (struct sockaddr_in *)addr->addr;
                return (sa->sin_addr.s_addr);
            }
        }
    }
    return (-1);
}

static void    option_h()
{
    display_help();
    free_all_malloc();
    exit(0);
}

static void    parse_input(t_parsed_cmd *parsed_cmd, int ac, char **av)
{
    if (ac < 2)
        option_h();
    *parsed_cmd = parse_options(ac, av);
    if (DEBUG_PARSING)
        debug_activated_options(parsed_cmd->act_options);
}

static void     alarm_handler(int signum)
{
    (void)signum;
    alarm(0);
    t_task  *task = create_task();

    task->scan_tracker_id   = 0; // TO DO
    task->task_type         = T_CHECK;
    enqueue_task(task);
}

static void     init_interface(char *first_interface_name, int *numeric_src_ip)
{
    pcap_if_t           *interfaces = NULL;

    interfaces = find_devices();
    debug_interfaces(interfaces);
    *numeric_src_ip = get_source_numeric_ip(interfaces);
    ft_strcpy(first_interface_name,  interfaces->name);
    pcap_freealldevs(interfaces);
    assert(*numeric_src_ip != -1 && "numeric src ip is -1");
}

static void     check_file_option(t_parsed_cmd parsed_cmd)
{
    int file_input;
    int one_target;

    file_input = is_activated_option(parsed_cmd.act_options, 'f');
    one_target = ft_lst_size(parsed_cmd.not_options);

    if ((!file_input && one_target != 1)  || (file_input && one_target >=1))
        exit_error_free("usage error: You can only supply either a file or a single target address as inputs\n");
}

static void     init_signal()
{
    struct sigaction    sa;

    ft_bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = alarm_handler;  // Set the handler function
    sa.sa_flags = 0;                // Use default flags
    sigemptyset(&sa.sa_mask);       // No signals blocked during handler
    if (sigaction(SIGALRM, &sa, NULL) == -1)
        exit_error_free("sigaction: %s\n", strerror(errno));
}

int             main(int ac, char **av)
{
    t_data              dt;
    t_parsed_cmd        parsed_cmd;
    int                 numeric_src_ip;
    char                first_interface_name[255];

    parse_input(&parsed_cmd, ac, av);
    init_signal();
    if (is_activated_option(parsed_cmd.act_options, 'h'))
        option_h();
    check_file_option(parsed_cmd);
    init_interface(first_interface_name, &numeric_src_ip);
    init_data(&dt, &parsed_cmd);                             // this needs to be done only once
    display_nmap_init(&dt);
    if (is_activated_option(parsed_cmd.act_options, 'f'))
        nmap_multiple_hosts(&dt, parsed_cmd, first_interface_name, numeric_src_ip);
    else
        nmap(&dt, parsed_cmd.not_options->content, first_interface_name, numeric_src_ip);
    display_nmap_end(&dt);
    free_all_malloc();
    return (0);
}
