SRCFILES=main.c

OBJSRC=$(SRCFILES:.c=.o)
OBJDIR=obj

SRCDIR=srcs
SRC=$(addprefix $(SRCDIR)/, $(SRCFILES))
OBJ=$(addprefix $(OBJDIR)/, $(OBJSRC))

NAME=malcom
CFLAGS=-Wall -Wextra -Wpedantic -g

vpath %.c srcs

all: $(NAME)


$(NAME): $(OBJ)
	cc $(CFLAGS)  $(OBJ) -o $(NAME)

obj/%.o: %.c
	mkdir -p obj
	cc $(CFLAGS) -c $< -o  $@


 
clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -rf $(NAME)

re: fclean all



.PHONY: all clean fclean re