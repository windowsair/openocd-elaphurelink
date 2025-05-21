CC = cc
CFLAGS = -Wall -Wextra -g -DHAVE_CONFIG_H
PKGCONFIG = pkg-config

CFLAGS += $(shell $(PKGCONFIG) --cflags libuv)
LDFLAGS = $(shell $(PKGCONFIG) --libs libuv) -pthread

CFLAGS += -I. -I./helper

TARGET = unit_test
SRCS = ../cmsis_dap_elaphurelink.c ./unit_test.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
