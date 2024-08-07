#include "../includes/ft_nmap.h"

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
            exit_error_free("malloc failure.\n");
        if (ft_strlen(param) <= 0 || ft_strlen(param) > MAX_SCANS)
            exit_error_free("invalid scans number.\n");
        for (int i = 0; param[i]; i++)
        {
            if (is_valid_scan_char(param[i]))
            {
                e_scan_type scan_type = char_to_scan_type(param[i]);
                if (scan_type != UNKNOWN)
                    scans_present[scan_type] = TRUE;
                else
                    exit_error_free("invalid scan value: '%c'\n", param[i]);
            }
            else
                exit_error_free("invalid scan value: '%c'\n", param[i]);
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

static int my_isspace(int c)
{
    return (c == ' ' || // space
            c == '\t' || // horizontal tab
            c == '\n' || // newline
            c == '\v' || // vertical tab
            c == '\f' || // form feed
            c == '\r');  // carriage return
}

//check for duplicated and don't insert them, just warn
void option_p(t_data *dt)
{
    int n_dup = 0;

    if (is_activated_option(dt->act_options, 'p'))
    {
        const char *ptr = get_option(dt->act_options, 'p')->param;

        dt->n_ports = 0;
        
        while (*ptr != '\0')
        {
            if (my_isspace(*ptr))
                return ;
            // Parse single integer or range
            int start, end;
            if (ft_isdigit(*ptr))
            {
                start = ft_atoi(ptr);
                end = start;

                if (start <= 0 || start > 65535 )
                    exit_error_free("Invalid port number <%d>.\n", start);

                while (ft_isdigit(*ptr))
                    ptr++;
                if (*ptr == '-')
                {
                    ptr++;
                    if (ft_isdigit(*ptr))
                        end = ft_atoi(ptr);
                    else
                        exit_error_free("Missing end of range.\n");
                }
                for (int i = start; i <= end ; i++)
                {
                    int dup = 0;
                    for (int ii = 0; ii < dt->n_ports; ii++)
                    {
                            if (dt->arg_ports[ii] == i)
                            {
                                dup = 1;
                                n_dup++;
                                break;
                            }
                        }
                    if (!dup)
                    {
                        if (dt->n_ports < 1024)
                            dt->arg_ports[dt->n_ports++] = i;
                        else
                            exit_error_free("too many ports.\n");
                    }
                    while (ft_isdigit(*ptr))
                        ptr++;
                }
            } 
            else
                exit_error_free("Invalid token <%c> in port arg.\n", *ptr);
            if (*ptr == ',') // If there's a comma, move to the next segment
                ptr++;
        }
    }else{
        dt->n_ports = MAX_PORTS;
        for (int i = 0; i < MAX_PORTS; i++)
            dt->arg_ports[i] = i+1;
    }
    dt->first_port = &dt->arg_ports[0];
    dt->last_port = &dt->arg_ports[dt->n_ports - 1];
    
    if (n_dup > 0)
        warning("duplicate ports detected.\n");
}

void   option_v(t_data *dt)
{
    if (is_activated_option(dt->act_options, 'v'))
        g_verbose = TRUE;
    else
        g_verbose = FALSE;
}

void   option_n(t_data *dt)
{
    if (is_activated_option(dt->act_options, 'n'))
        dt->no_dns = TRUE;
    else
        dt->no_dns = FALSE;
}

void   option_r(t_data *dt)
{
    if (is_activated_option(dt->act_options, 'r'))
        dt->reason = TRUE;
    else
        dt->reason = FALSE;
}

void   option_th(t_data *dt)
{
    int  threads    = 0;
    char *param     = NULL;

    if (is_activated_option(dt->act_options, 't'))
    {
        param = ft_strdup(get_option(dt->act_options, 't')->param);
        if (param == NULL)
            exit_error_free("malloc failure.\n");
        if (ft_isstrnum(param) == 0)
            exit_error_free("invalid value: (`%s' near `%s')\n", param, "t");
        threads = ft_atoi(param);
        if (threads < 0)
            exit_error_free("option value too small: %d\n", threads);
        else if (threads > 250)
            exit_error_free("option value too big: %d\n", threads);
        else
            dt->threads = threads + THREADS_NB;
    }
    else
        dt->threads = THREADS_NB;
}

void   option_m(t_data *dt)
{
    int  max_retries   = 0;
    char *param     = NULL;

    if (is_activated_option(dt->act_options, 'm'))
    {
        param = ft_strdup(get_option(dt->act_options, 'm')->param);
        if (param == NULL)
            exit_error_free("malloc failure.\n");
        if (ft_isstrnum(param) == 0)
            exit_error_free("invalid value: (`%s' near `%s')\n", param, param);
        max_retries = ft_atoi(param);
        if (max_retries <= 0)
            exit_error_free("option value too small: %d\n", max_retries);
        else if (max_retries > 50)
            exit_error_free("option value too big: %d\n", max_retries);
        else
            dt->max_retries = max_retries;
    }
    else
        dt->max_retries = MAX_RETRIES;
}

void   option_d(t_data *dt)
{
    int  probes_delay   = 0;
    char *param     = NULL;

    if (is_activated_option(dt->act_options, 'd'))
    {
        param = ft_strdup(get_option(dt->act_options, 'd')->param);
        if (param == NULL)
            exit_error_free("malloc failure.\n");
        if (ft_isstrnum(param) == 0)
            exit_error_free("invalid value: (`%s' near `%s')\n", param, param);
        probes_delay = ft_atoi(param);
        if (probes_delay <= 0)
            exit_error_free("option value too small: %d\n", probes_delay);
        else if (probes_delay > 50)
            exit_error_free("option value too big: %d\n", probes_delay);
        else
            dt->probes_delay = probes_delay;
    }
    else
        dt->probes_delay = PROBES_DELAY;
}

void    init_options_params(t_data *dt)
{
    option_p(dt);
    option_s(dt);
    option_th(dt);
    option_r(dt);
    option_n(dt);
    option_v(dt);
    option_m(dt);
    option_d(dt);
}
