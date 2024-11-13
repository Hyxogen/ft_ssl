NAME	:= ft_ssl

CC		?= cc

LIBFT_DIR	:= libft
LIBFT_LIB	:= $(LIBFT_DIR)/libft.a

SRC_DIR		:= src
OBJ_DIR		:= build
DEP_DIR		:= build

SRC_FILES	:= $(shell find $(SRC_DIR) -name '*.c')
OBJ_FILES	:= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))
DEP_FILES	:= $(patsubst $(SRC_DIR)/%.c,$(DEP_DIR)/%.d,$(SRC_FILES))

CFLAGS		:= -Wall -Wextra -MMD -Iinclude -I$(LIBFT_DIR)/include -masm=intel
LFLAGS		:=

ifndef config
	config	:= debug
endif


ifeq ($(config),debug)
	CFLAGS	+= -O0 -g3
else ifeq ($(config),release)
	CFLAGS	+= -O1 -g -fno-inline
else ifeq ($(config),distr)
	CFLAGS	+= -O3 -g0 -DNDEBUG
	LFLAGS	+= -flto
else
$(error "Unknown config '$(config)'. Available: debug, release, distr")
endif

ifndef san
	san := addr
endif

ifeq ($(san), addr)
	CFLAGS += -fsanitize=address,undefined
	LFLAGS += -fsanitize=address,undefined
else ifeq ($(san), mem)
	CFLAGS += -fsantizie=memory,undefined -fsanitize-memory-track-origins
	LFLAGS += -fsantizie=memory,undefined -fsanitize-memory-track-origins
else ifeq ($(san), none)
else
$(error "$(san): invalid sanitizer")
endif

all: $(NAME)

$(NAME): $(OBJ_FILES) $(LIBFT_LIB)
	$(CC) $(OBJ_FILES) $(LIBFT_LIB) $(LFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c Makefile
	@mkdir -p $(@D)
	$(CC) -c $< -o $@ $(CFLAGS)

$(LIBFT_LIB): Makefile
	@${MAKE} -C $(LIBFT_DIR) san=$(san)

clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(DEP_DIR)

fclean:
	@${MAKE} clean
	@${MAKE} -C $(LIBFT_DIR) fclean
	rm -f $(NAME)

re:
	@${MAKE} fclean
	@${MAKE}

-include $(DEP_FILES)
.PHONY: all clean fclean re
