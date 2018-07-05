BIN = mping
OBJS = $(BIN:=.o) list.o

CC = gcc
CFLAGS = -g -O2 -Wall -D_GNU_SOURCE
LDFLAGS = -lpthread -pthread

all: $(BIN)
	@chown root mping || echo You must compile as root to set sticky bit
	@chmod u+s mping
	@-rm -rf $(OBJS) *~
	@echo mping binary created OK

mping: $(OBJS)

install: mping
	@-rm -rf $(OBJS) *~
	cp mping /usr/bin/mping

uninstall:
	rm /usr/bin/mping

clean:
	-rm -rf $(OBJS) $(BIN) *~
