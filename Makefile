.PHONY: all clean

all: wmond

wmond: iwlib.c iwevent.c iwlib.h
	$(CC) $(CPPFLAGS) $(CFLAGS) iwlib.c iwevent.c $(LDFLAGS) -lm -o $@

clean:
	rm -rf *.o wmond
