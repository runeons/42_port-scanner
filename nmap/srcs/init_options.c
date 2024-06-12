#include "../includes/ft_nmap.h"

// void   option_q(t_data *dt)
// {
//     int  nb_probes  = 0;
//     char *param     = NULL;

//     if (is_activated_option(dt->act_options, 'q'))
//     {
//         param = ft_strdup(get_option(dt->act_options, 'q')->param);
//         if (param == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         if (ft_isstrnum(param) == 0)
//             exit_options_error("ft_nmap: invalid value: (`%s' near `%s')\n", param, param);
//         nb_probes = ft_atoi(param);
//         if (nb_probes <= 0)
//             exit_options_error("ft_nmap: option value too small: %d\n", nb_probes);
//         else if (nb_probes > 255)
//             exit_options_error("ft_nmap: option value too big: %d\n", nb_probes);
//         else
//             dt->nb_probes = nb_probes;
//     }
//     else
//         dt->nb_probes = NB_PROBES;
// }

// void   option_m(t_data *dt)
// {
//     int  max_ttl   = 0;
//     char *param     = NULL;

//     if (is_activated_option(dt->act_options, 'm'))
//     {
//         param = ft_strdup(get_option(dt->act_options, 'm')->param);
//         if (param == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         if (ft_isstrnum(param) == 0)
//             exit_options_error("ft_nmap: invalid value: (`%s' near `%s')\n", param, param);
//         max_ttl = ft_atoi(param);
//         if (max_ttl <= 0)
//             exit_options_error("ft_nmap: option value too small: %d\n", max_ttl);
//         else if (max_ttl > 255)
//             exit_options_error("ft_nmap: option value too big: %d\n", max_ttl);
//         else
//             dt->max_ttl = max_ttl;
//     }
//     else
//         dt->max_ttl = MAX_TTL;
// }

// void   option_w(t_data *dt)
// {
//     int  reply_timeout  = 0;
//     char *param         = NULL;

//     if (is_activated_option(dt->act_options, 'w'))
//     {
//         param = ft_strdup(get_option(dt->act_options, 'w')->param);
//         if (param == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         if (ft_isstrnum(param) == 0)
//             exit_options_error("ft_nmap: invalid value: (`%s' near `%s')\n", param, param);
//         reply_timeout = ft_atoi(param);
//         if (reply_timeout <= 0)
//             exit_options_error("ft_nmap: option value too small: %d\n", reply_timeout);
//         else if (reply_timeout > 255)
//             exit_options_error("ft_nmap: option value too big: %d\n", reply_timeout);
//         else
//             dt->reply_timeout = reply_timeout;
//     }
//     else
//         dt->reply_timeout = REPLY_TIMEOUT;
// }

// void   option_z(t_data *dt)
// {
//     float  interval       = 0;
//     int    interval_us    = 0;
//     char   *param         = NULL;

//     if (is_activated_option(dt->act_options, 'z'))
//     {
//         param = ft_strdup(get_option(dt->act_options, 'z')->param);
//         if (param == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         if (ft_isstrfloat(param) == 0)
//             exit_options_error("ft_nmap: invalid value (`%s' near `%s')\nTry 'ft_nmap --help' for more information.\n", param, param);
//         interval = ft_atof(param);
//         interval_us = (int)(interval * 1000000);
//         if (interval_us < 200000)
//             exit_options_error("ft_nmap: option value too small: %s\n", param);
//         else if (interval > 2048)
//             exit_options_error("ft_nmap: option value too big: %s\n", param);
//         else
//             dt->probes_interval_us = interval_us;
//     }
//     else
//         dt->probes_interval_us = PROBES_INTERVAL_S * 1000000;
// }

int     is_in_scans(char c, int scans[MAX_SCANS])
{
    for (int i = 0; i < MAX_SCANS; i++)
    {
        if (scans[i == c])
            return TRUE;
    }
    return FALSE;
}

e_scan_type char_to_scan_type(char c)
{
    switch (c)
    {
        case 'S':
            return SYN;
        case 'A':
            return ACK;
        case 'U':
            return UDP;
        case 'F':
            return FIN;
        case 'N':
            return NUL;
        case 'X':
            return XMAS;
        case 'I':
            return ICMP;
        default:
            return UNKNOWN;
    }
}

int is_valid_scan_char(char c)
{
    return (ft_strchr(SCAN_CHARS, c) != NULL);
}


void   option_s(t_data *dt)
{
    int     unique_scans[MAX_SCANS];
    char    *param      = NULL;
    int     scans_present[MAX_SCANS] = {FALSE};

    ft_memset(unique_scans, 0, sizeof(unique_scans));
    if (is_activated_option(dt->act_options, 's'))
    {
        param = ft_strdup(get_option(dt->act_options, 's')->param);
        if (param == NULL)
            exit_options_error("ft_nmap: malloc failure.\n");
        if (ft_strlen(param) <= 0 || ft_strlen(param) > MAX_SCANS)
            exit_options_error("ft_nmap: invalid scans number.\n");
        for (int i = 0; param[i]; i++)
        {
            if (is_valid_scan_char(param[i]))
            {
                e_scan_type scan_type = char_to_scan_type(param[i]);
                if (scan_type != UNKNOWN)
                    scans_present[scan_type] = TRUE;
                else
                    exit_options_error("ft_nmap: invalid scan value: '%c'\n", param[i]);
            }
            else
                exit_options_error("ft_nmap: invalid scan value: '%c'\n", param[i]);
        }
        int count = 0;
        for (int i = 0; i < MAX_SCANS; i++)
        {
            if (scans_present[i])
                dt->unique_scans[count++] = (e_scan_type)i;
        }
        g_scan_types_nb = count;
    }
    else
    {
        for (int i = 0; i < MAX_SCANS; i++)
        {
            dt->unique_scans[i] = (e_scan_type)i;
            scans_present[i] = TRUE;
        }
        g_scan_types_nb = MAX_SCANS;
    }
}

static int my_isspace(int c) {
    return (c == ' ' || // space
            c == '\t' || // horizontal tab
            c == '\n' || // newline
            c == '\v' || // vertical tab
            c == '\f' || // form feed
            c == '\r');  // carriage return
}

//check for duplicated and don't insert them, just warn
void option_p(t_data *dt){//, int *output, int *output_size) {
    int n_dup = 0;

    if (is_activated_option(dt->act_options, 'p')){
        const char *ptr = get_option(dt->act_options, 'p')->param;

        dt->n_ports = 0;
        
        while (*ptr != '\0') {
            if (my_isspace(*ptr)) {
                return ;
            }

            // Parse single integer or range
            int start, end;
            if (ft_isdigit(*ptr)) {
                start = ft_atoi(ptr);
                end = start;

                if (start <= 0 || start > 65535 ){
                    printf("Invalid port number <%d>\n", start);
                    exit(1);
                }

                while (ft_isdigit(*ptr))
                    ptr++;
                if (*ptr == '-') {
                    ptr++;
                    if (ft_isdigit(*ptr)) {
                        end = ft_atoi(ptr);
                    }
                    else
                    {
                        exit_error("Missing end of range\n");
                    }
                }

                for (int i = start; i <= end ; i++) {
                    int dup = 0;
                    for (int ii = 0; ii < dt->n_ports; ii++){
                            if (dt->arg_ports[ii] == i){
                                dup = 1;
                                n_dup++;
                                break;
                            }
                        }
                    if (!dup) {
                        if (dt->n_ports < 1024)
                            dt->arg_ports[dt->n_ports++] = i;
                        else{
                            printf("TOO MANY PORTS\n");
                            exit(1);
                        }
                    }

                    while (ft_isdigit(*ptr))
                        ptr++;
                }
                printf("\n");
            } 
            else{
                printf("Invalid token <%c> in port arg\n", *ptr);
                exit(1);
            }

            // If there's a comma, move to the next segment
            if (*ptr == ',') {
                ptr++;
            }
        }
    }else{
        dt->n_ports = MAX_PORTS;
        for (int i = 0; i < MAX_PORTS; i++)
            dt->arg_ports[i] = i+1;
    }
    dt->first_port = &dt->arg_ports[0];
    dt->last_port = &dt->arg_ports[dt->n_ports - 1];

    if (n_dup > 0)
        printf("Warning: duplicate ports detected\n");
}

// void   option_p(t_data *dt)
// {
//     char    *param     = NULL;
//     char    **tmp      = NULL;
//     int     first_port = FIRST_PORT;
//     int     last_port  = LAST_PORT;
//     //int     n_ports    = 0;

//     if (is_activated_option(dt->act_options, 'p'))
//     {
//         param = ft_strdup(get_option(dt->act_options, 'p')->param);
//         printf("Port Input: %s\n", param);
//         if (param == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         tmp = ft_split(param, '-');
//         for 
//         if (tmp == NULL)
//             exit_options_error("ft_nmap: malloc failure.\n");
//         if (ft_tablen(tmp) != 1 && ft_tablen(tmp) != 2)
//             exit_options_error("ft_nmap: invalid ports range.\n");
//         for (int i = 0; tmp && tmp[i]; i++)
//             if (ft_isstrnum(tmp[i]) == 0)
//                 exit_options_error("ft_nmap: invalid port value '%s'\n", tmp[i]);
//         first_port = ft_atoi(tmp[0]);
//         if (first_port < MIN_PORT || first_port > MAX_PORT)
//             exit_options_error("ft_nmap: port value out of range: %d\n", first_port);
//         if (tmp[1])
//         {
//             last_port = ft_atoi(tmp[1]);
//             if (last_port < MIN_PORT || last_port > MAX_PORT)
//                 exit_options_error("ft_nmap: port value out of range: %d\n", last_port);
//         }
//         else
//             last_port = first_port;
//         if (first_port > last_port)
//             exit_options_error("ft_nmap: port range not ordered.\n");
//         if ((last_port - first_port) >= MAX_PORT_RANGE)
//             exit_options_error("ft_nmap: port range too high (max 1024).\n");
//         dt->first_port = first_port;
//         dt->last_port = last_port;
//     }
//     exit(0);
// }

void   option_v(t_data *dt)
{
    if (is_activated_option(dt->act_options, 'v'))
        g_verbose = TRUE;
    else
        g_verbose = FALSE;
}

void   option_th(t_data *dt)
{
    int  threads    = 0;
    char *param     = NULL;

    if (is_activated_option(dt->act_options, 't'))
    {
        param = ft_strdup(get_option(dt->act_options, 't')->param);
        if (param == NULL)
            exit_options_error("ft_nmap: malloc failure.\n");
        if (ft_isstrnum(param) == 0)
            exit_options_error("ft_nmap: invalid value: (`%s' near `%s')\n", param, "t");
        threads = ft_atoi(param);
        if (threads < 0)
            exit_options_error("ft_nmap: option value too small: %d\n", threads);
        else if (threads > 250)
            exit_options_error("ft_nmap: option value too big: %d\n", threads);
        else
            dt->threads = threads + THREADS_NB;
    }
    else
        dt->threads = THREADS_NB;
}

void    init_options_params(t_data *dt)
{
    option_p(dt);
    option_s(dt);
    option_th(dt);
    // option_i(dt);
    // option_n(dt);
    option_v(dt);
    // option_f(dt);
}
