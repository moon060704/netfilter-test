CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lnetfilter_queue

TARGET = netfilter-test
OBJS = main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
