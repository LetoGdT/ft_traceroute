NAME		:=	ft_traceroute
SRCS		:=	srcs/main.c \
				srcs/dns.c\
				srcs/checksum.c

HDRS		:=	incs/ft_traceroute.h

OBJS		:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS))))

LIBFT_DIR	:= libft
LIBS		:= $(LIBFT_DIR)/libft.a

CC			:=	gcc
CFLAGS		:=	-Iincs
LDFLAGS		:=  -lm
RM			:=	rm -f

all:			$(NAME)

$(NAME):		$(OBJS) | libs
				@echo "Linking $(NAME)"
				@$(CC) $^ -o $@ $(LDFLAGS) $(LIBS)

objs/%.o:		srcs/%.c $(HDRS)
				@mkdir -p objs
				@echo "Compiling $<"
				@$(CC) $(CFLAGS) -c $< -o $@

libs:
				@echo "Making libft"
				@$(MAKE) -C $(LIBFT_DIR)

clean:
				@echo "Deleting object files"
				@$(RM) $(OBJS)
				@echo "Cleaning libs"
				@$(MAKE) -s -C $(LIBFT_DIR) clean

fclean:			clean
				@$(RM) $(NAME)
				@echo "Force cleaning libs"
				@$(MAKE) -s -C $(LIBFT_DIR) fclean

re: 			fclean all

.PHONY:			all clean fclean re