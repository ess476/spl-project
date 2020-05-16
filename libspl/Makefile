SO_TARGET = libspl.so
STATIC_TARGET = libspl.a

SRCS  = $(shell find ./     -type f -name *.c)
HEADS = $(shell find ./include -type f -name *.h)
OBJS = $(SRCS:.c=.o)

INCLUDES = -I./include
CFLAGS = -g -Wall $(INCLUDES) -lseccomp 
LDFLAGS = -lseccomp

.PHONY: all clean

all: $(SO_TARGET) $(STATIC_TARGET)

$(SO_TARGET): $(OBJS) $(HEADS)
	$(CC) -o $@ $^ $(LDFLAGS) -shared

$(STATIC_TARGET): $(OBJS) $(HEADS)
	$(AR) rcs $@ $^

clean:
	$(RM) $(OBJS) $(TARGET)