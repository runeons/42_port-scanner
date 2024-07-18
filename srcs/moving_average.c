#include "../includes/ft_nmap.h"

void    add_value(t_mavg *ma, double value)
{
    // Subtract the value that is exiting the window
    ma->sum -= ma->values[ma->index];
    // Add the new value to the window
    ma->values[ma->index] = value;
    // Add the new value to the sum
    ma->sum += value;
    // Move to the next index
    ma->index = (ma->index + 1) % WINDOW_SIZE;
    // Keep track of the number of values added
    if (ma->count < WINDOW_SIZE)
        ma->count++;
}

double  get_moving_average(t_mavg *ma)
{
    if (ma->count == 0)
        return 0.0; // Avoid division by zero
    return ma->sum / ma->count;
}
