/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin_multi.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/18 09:43:32 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 09:43:47 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

static void	*join(char **ret, char *arg, int *retsize)
{
	char	*tmp;
	int		size;

	size = ft_strlen(arg);
	tmp = mmalloc(sizeof(char) * (*retsize + size + 1));
	ft_memcpy(tmp, *ret, *retsize);
	ft_memcpy(tmp + *retsize, arg, size);
	*retsize += size;
	tmp[*retsize] = '\0';
	mfree((void **)ret);
	*ret = tmp;
	return (tmp);
}

char	*ft_strjoin_multi(int nb_str, ...)
{
	char	*arg;
	char	*ret;
	va_list	ap;
	int		size;

	ret = NULL;
	size = 0;
	va_start(ap, nb_str);
	while (nb_str--)
	{
		arg = va_arg(ap, char *);
		if (!arg)
			continue ;
		if (!ret)
		{
			ret = ft_strdup(arg);
			if (!ret)
				return (NULL);
			size = ft_strlen(ret);
		}
		else if (join(&ret, arg, &size) == NULL)
			return (NULL);
	}
	va_end(ap);
	return (ret);
}
