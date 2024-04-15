#ifndef UTILS_OPTIONS_H
# define UTILS_OPTIONS_H

# include "stdio.h"
# include <libft.h>

# define ARRAY_SIZE(arr)    (sizeof(arr) / sizeof((arr)[0])) // int option_count = ARRAY_SIZE(allowed_options);
# define CMD_NAME           "ft_nmap"

typedef struct s_parsed_cmd
{
    t_lst *act_options;
    t_lst *not_options;
}              t_parsed_cmd;

typedef struct s_option
{
    char    id;
    char    *name;
    int     need_param;
    char    *param_name;
    char    *param;
    char    *description;
}              t_option;

void            exit_options_error(const char *msg, ...);
void            display_help();
void            display_long_usage();
void            display_short_usage();
void            debug_activated_options(t_lst *act_options);
int             is_activated_option(t_lst *act_options, char c);
t_parsed_cmd    parse_options(int ac, char **av);
t_option        *get_option(t_lst *act_options, char c);
void            print_option(t_lst *act_options, char c);

#endif