.PHONY: all clean

all: wmond


wmond: iwlib.c iwevent.c iwlib.h
	$(CC) $(CFLAGS) iwlib.c iwevent.c -o $@ -lm

clean:
	rm -rf *.o wmond
