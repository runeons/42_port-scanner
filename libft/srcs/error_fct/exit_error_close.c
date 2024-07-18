#include <libft.h>

void exit_error_close(int socket, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    if (socket > 0)
        close(socket);
    exit(1);
}
