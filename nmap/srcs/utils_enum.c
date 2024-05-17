#include "../includes/ft_nmap.h"

char  *task_type_string(e_task_type task_type)
{
    switch (task_type)
    {
        case T_SEND:
            return "T_SEND";
        case T_RECV:
            return "T_RECV";
        case T_EMPTY:
            return "T_EMPTY";
        default:
            return "Invalid";
    }
}

char  *scan_type_string(e_scan_type scan_type)
{
    switch (scan_type)
    {
        case ICMP:
            return "ICMP";
        case SYN:
            return "SYN";
        case ACK:
            return "ACK";
        case UDP:
            return "UDP";
        case FIN:
            return "FIN";
        case NUL:
            return "NUL";
        case XMAS:
            return "XMAS";
        case UNKNOWN:
            return "UNKNOWN";
        default:
            return "Invalid";
    }
}

char  *response_string(e_response response)
{
    switch (response)
    {
        case IN_PROGRESS:
            return "IN_PROGRESS";
        case TCP_SYN_ACK:
            return "TCP_SYN_ACK";
        case TCP_RST:
            return "TCP_RST";
        case UDP_ANY:
            return "UDP_ANY";
        case ICMP_UNR_C_3:
            return "ICMP_UNR_C_3";
        case ICMP_UNR_C_NOT_3:
            return "ICMP_UNR_C_NOT_3";
        case NO_RESPONSE:
            return "NO_RESPONSE";
        case OTHER:
            return "OTHER";
        case ICMP_ECHO_OK:
            return "ICMP_ECHO_OK";
        default:
            return "Invalid";
    }
}

char  *conclusion_string(e_conclusion conclusion)
{
    switch (conclusion)
    {
        case NOT_CONCLUDED:
            return "NOT_CONCLUDED";
        case OPEN:
            return "OPEN";
        case CLOSED:
            return "CLOSED";
        case FILTERED:
            return "FILTERED";
        case OPEN_FILTERED:
            return "OPEN_FILTERED";
        case UNFILTERED:
            return "UNFILTERED";
        default:
            return "Invalid";
    }
}