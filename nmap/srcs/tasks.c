#include "ft_nmap.h"

pthread_mutex_t mutex       = PTHREAD_MUTEX_INITIALIZER;

void    enqueue_task(t_data *dt, t_task *task)
{
    pthread_mutex_lock(&mutex);
    ft_lst_add_node_back(&dt->queue, ft_lst_create_node(task));
    print_info_task("Enqueued task", task->id);
    g_queued++;
    pthread_mutex_unlock(&mutex);
}

t_task *dequeue_task(t_data *dt)
{
    pthread_mutex_lock(&mutex);
    t_lst       *first_node = NULL;
    t_task *task = NULL;

    if (dt->queue == NULL || ft_lst_size(dt->queue) == 1)
        return NULL;
    first_node = ft_lst_get_first_node(&dt->queue);
    if (first_node)
    {
        task = first_node->content;
        ft_lst_remove_node(&dt->queue, first_node);
    }
    else
        return NULL;  
    pthread_mutex_unlock(&mutex);
    return task;
};

t_task    *create_task(int socket, struct sockaddr_in target_address, int dst_port)
{
    t_task *task = NULL;

    task = mmalloc(sizeof(t_task));
    if (task == NULL)
        exit_error_close_socket("ft_nmap: malloc failure.", socket);
    task->id                = g_task_id++;
    task->task_type         = T_SEND;
    task->scan_type         = ICMP;
    task->dst_port          = dst_port;
    ft_memset(&(task->target_address), 0, sizeof(struct sockaddr_in));
    task->target_address    = target_address;

    return task;
}

void    init_queue(t_data *dt)
{
    for (int i = 0; i <= g_max_send; i++)
    {
        t_task *task;

        task = create_task(dt->socket, dt->target_address, dt->dst_port + i);
        enqueue_task(dt, task);
    }
}
