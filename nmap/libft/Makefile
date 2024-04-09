
# *** NAME - CC - FLAGS ****************************************************** #

NAME = libft.a

CC = clang

CFLAGS = #-Wall -Wextra -Werror

# *** PROJECT HEADER ********************************************************* #

HDIR					=	$(addprefix -I, $(HEADER_DIR))

HEAD					=	$(addprefix $(HEADER_DIR), $(HEADER))

HEADER_DIR				=	\
							./includes/

HEADER							=	\
							get_next_line.h \
							libft.h \
							libft_lst.h \

# *** SRCS ******************************************************************* #

SRCS_DIR				=	./srcs/


DOUBLE_LINKED_FCT				=	\
							double_linked_fct/libft_lst_add.c \
							double_linked_fct/libft_lst_general.c \
							double_linked_fct/libft_lst_print.c \
							double_linked_fct/libft_lst_del.c \
							double_linked_fct/libft_lst_get.c \
							double_linked_fct/libft_malloc_free.c \

GNL_FCT							=	\
							gnl_fct/get_next_line.c \
							gnl_fct/get_next_line_utils.c \

IS_FCT							=	\
							is_fct/ft_isalnum.c \
							is_fct/ft_isalpha.c \
							is_fct/ft_isascii.c \
							is_fct/ft_isdigit.c \
							is_fct/ft_isprint.c \
							is_fct/ft_isstrfloat.c \
							is_fct/ft_ishex.c \
							is_fct/ft_isnum.c \
							is_fct/ft_isstrnum.c \

LIST_FCT						=	\
							list_fct/ft_lstadd_back.c \
							list_fct/ft_lstclear.c \
							list_fct/ft_lstiter.c \
							list_fct/ft_lstmap.c \
							list_fct/ft_lstsize.c \
							list_fct/ft_lstadd_front.c \
							list_fct/ft_lstdelone.c \
							list_fct/ft_lstlast.c \
							list_fct/ft_lstnew.c \

MEM_FCT							=	\
							mem_fct/ft_bzero.c \
							mem_fct/ft_memalloc.c \
							mem_fct/ft_memchr.c \
							mem_fct/ft_memcpy.c \
							mem_fct/ft_memset.c \
							mem_fct/ft_calloc.c \
							mem_fct/ft_memccpy.c \
							mem_fct/ft_memcmp.c \
							mem_fct/ft_memmove.c \
							mem_fct/ft_realloc.c \

NUMBER_FCT						= \
							number_fct/ft_cap.c \
							number_fct/ft_atoi.c \
							number_fct/ft_atof.c \
							number_fct/ft_intlen.c \
							number_fct/ft_itoa.c \
							number_fct/ft_sqrt.c \

TAB_FCT						= \
							tab_fct/ft_free_tab.c \
							tab_fct/ft_tablen.c \

PUT_FCT							= \
							put_fct/ft_putchar_fd.c \
							put_fct/ft_putendl_fd.c \
							put_fct/ft_putnbr_fd.c \
							put_fct/ft_putstr_fd.c \
							put_fct/ft_putstrchar_fd.c \

STR_FCT							= \
							str_fct/ft_split.c \
							str_fct/ft_strcpy.c \
							str_fct/ft_strjoin.c \
							str_fct/ft_strlcpy.c \
							str_fct/ft_strncmp.c \
							str_fct/ft_strnstr.c \
							str_fct/ft_substr.c \
							str_fct/ft_strchr.c \
							str_fct/ft_strdel.c \
							str_fct/ft_strjoinfree.c \
							str_fct/ft_strjoin_multi.c \
							str_fct/ft_strlen.c \
							str_fct/ft_strndup.c \
							str_fct/ft_strrchr.c \
							str_fct/ft_tolower.c \
							str_fct/ft_strcmp.c \
							str_fct/ft_strdup.c \
							str_fct/ft_strlcat.c \
							str_fct/ft_strmapi.c \
							str_fct/ft_strnew.c \
							str_fct/ft_strtrim.c \
							str_fct/ft_toupper.c \

ERROR_FCT						= \
							error_fct/exit_error.c \
							error_fct/exit_error_close.c \
							error_fct/warning_error.c \

SRCS_LIST				=	\
							$(DOUBLE_LINKED_FCT) \
							$(GNL_FCT) \
							$(IS_FCT) \
							$(LIST_FCT) \
							$(MEM_FCT) \
							$(TAB_FCT) \
							$(NUMBER_FCT) \
							$(PUT_FCT) \
							$(STR_FCT) \
							$(ERROR_FCT) \

SRCS					=	$(addprefix $(SRCS_DIR), $(SRCS_LIST))

# *** OBJS ******************************************************************* #

OBJS_DIR				=	./objs/

OBJS_LIST				=	$(patsubst %.c, %.o, $(SRCS_LIST))

OBJS					=	$(addprefix $(OBJS_DIR), $(OBJS_LIST))

# OBJ = $(SRCS:.c=.o)

OPTION = -c -I .

all: $(OBJS) $(SRCS) $(NAME)

$(NAME): $(OBJS) $(SRCS)
	@ ar rcs $(NAME) $(OBJS)

	# $(CC) $(CFLAGS) $(OPTION) $(HDIR) $(SRCS)

$(OBJS_DIR)%.o: $(SRCS_DIR)%.c
	@ mkdir -p $(dir $@)
	@ $(CC) $(CFLAGS) $(HDIR) $(OPTION) -o $@ $<

clean:
	rm -rf $(OBJS_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean
