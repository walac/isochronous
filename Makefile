LIBUSB_FLAGS = $(shell pkg-config --cflags libusb-1.0)
WARN_FLAGS = -Wall -Wextra #-Werror
CFLAGS = -g3 $(WARN_FLAGS) -std=c99 -D_GNU_SOURCE=1 -D _POSIX_C_SOURCE=199309L $(LIBUSB_FLAGS)
LIBS = $(shell pkg-config --libs libusb-1.0)
OBJS = $(patsubst %.c,%.o,$(shell ls *.c))
EXE = iso-test

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(EXE)

.PHONY: clean distclean
