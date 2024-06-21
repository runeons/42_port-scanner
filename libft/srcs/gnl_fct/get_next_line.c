/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/12/09 09:45:51 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:09:02 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

int	get_next_line(int fd, char **line)
{
	static char	tokeep[BUFFER_SIZE + 1];
	char		buf[BUFFER_SIZE + 1];
	int			read_value;

	if (fd < 0 || !line || read(fd, buf, 0) < 0 || BUFFER_SIZE < 1)
		return (-1);
	*line = ft_calloc_gnl(1);
	if (!(*line))
		return (-1);
	if (*tokeep)
		*line = ft_strjoinfree(tokeep, *line, 2);
	while (ft_haseol(*line) == 0)
	{
		read_value = read(fd, buf, BUFFER_SIZE);
		buf[read_value] = '\0';
		*line = ft_strjoinfree(*line, buf, 1);
		if (read_value < BUFFER_SIZE && ft_haseol(*line) == 0)
		{
			tokeep[0] = '\0';
			return (0);
		}
	}
	ft_cut_line_create_tokeep(*line, tokeep);
	return (1);
}
