# Modified Makefile to allow for building of the standalone module

TITLE=pam_logpassword

LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LDLIBS = -lpam -lpam_misc -lsqlite3
LIBSHARED = $(TITLE).so

all: $(LIBSHARED)

$(LIBSHARED): $(LIBOBJ)
		ld --shared -o $@ $(LIBOBJ) $(LDLIBS)

clean:
	rm -f $(LIBOBJ) $(LIBSHARED) core *~

extraclean: clean
	rm -f *.a *.o *.so *.bak 

.c.o:	
	$(CC) $(CFLAGS) -c $< -o $@

