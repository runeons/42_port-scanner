#include <libft.h>

void exit_error_args(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    exit(1);
}
