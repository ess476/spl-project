TARGET = hello

SRCS  = $(shell find ./     -type f -name *.c)
HEADS = $(shell find ./include -type f -name *.h)
OBJS = $(SRCS:.c=.o)

INCLUDES = -I./include -I../libspl/include
LDFLAGS = ../libspl/libspl.a -lseccomp 
CFLAGS = -g -Wall $(INCLUDES)
.PHONY = all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(TARGET)
