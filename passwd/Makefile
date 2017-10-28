prefix=/opt/freesvr/audit/passwd
sbindir=${prefix}/sbin
sysconfdir=${prefix}/etc
logdir=${prefix}/log
tmpdir=${prefix}/tmp
target=freesvr-passwd
srcdir=.

INSTALL=/usr/bin/install -c
DESTDIR=
STRIP_OPT=-s

CC			= gcc
CFLAGS		= -g -O2 -Wall -o 
OBJFLAGS	= -Wall -O2 -c
INCLUDE		= -I/opt/freesvr/sql/include/mysql
LDFLAGS		= -L./ -L/opt/freesvr/sql/lib/
LIBS		= -lmysqlclient -lcrypto -lmail -lcrypt
CONFILE		= \"$(sysconfdir)/freesvr_passwd_config\"
TEMPDIR		= \"$(tmpdir)\"
PROGRAM		= \"$(target)\"
BINARYDIR   = \"$(sbindir)\"

all : $(target)

$(target) : main.o log.o config.o list.o fetch-candidate.o trie.o random.o flock.o ssh-pipe.o envelope.o windows.o
	$(CC) $(CFLAGS) $@ main.o log.o config.o list.o fetch-candidate.o trie.o random.o flock.o ssh-pipe.o envelope.o windows.o $(INCLUDE) $(LDFLAGS) $(LIBS)
main.o : main.c
	$(CC) $(OBJFLAGS) main.c $(INCLUDE) -DPROGRAM_NAME=$(PROGRAM)
log.o : log.c
	$(CC) $(OBJFLAGS) log.c $(INCLUDE) -DPROGRAM_NAME=$(PROGRAM)
config.o : config.c
	$(CC) $(OBJFLAGS) config.c -DCONFIG_FILE=$(CONFILE) $(INCLUDE)
list.o : list.c
	$(CC) $(OBJFLAGS) list.c -DCONFIG_FILE=$(CONFILE) $(INCLUDE)
fetch-candidate.o : fetch-candidate.c
	$(CC) $(OBJFLAGS) fetch-candidate.c -DCONFIG_FILE=$(CONFILE) $(INCLUDE)
trie.o : trie.c
	$(CC) $(OBJFLAGS) trie.c $(INCLUDE)
random.o : random.c
	$(CC) $(OBJFLAGS) random.c $(INCLUDE)
flock.o : flock.c
	$(CC) $(OBJFLAGS) flock.c $(INCLUDE) -DBINARY_PATH=$(BINARYDIR)
ssh-pipe.o : ssh-pipe.c
	$(CC) $(OBJFLAGS) ssh-pipe.c $(INCLUDE) -DBINARY_PATH=$(BINARYDIR) -DPROGRAM_NAME=$(PROGRAM) 
envelope.o : envelope.c
	$(CC) $(OBJFLAGS) envelope.c $(INCLUDE) -DTEMP_PATH=$(TEMPDIR)
windows.o : windows.c
	$(CC) $(OBJFLAGS) windows.c $(INCLUDE) 

clean:
	rm *.o
	rm $(target)

install : $(target) passwd_config autossh
	$(srcdir)/mkinstalldirs $(DESTDIR)$(sbindir)
	(umask 022 ; $(srcdir)/mkinstalldirs $(DESTDIR)$(PRIVSEP_PATH))
	$(INSTALL) -m 0755 $(STRIP_OPT) $(target) $(DESTDIR)$(sbindir)/$(target)
	$(INSTALL) -m 0755 $(STRIP_OPT) autossh $(DESTDIR)$(sbindir)/autossh

	$(srcdir)/mkinstalldirs $(DESTDIR)$(sysconfdir)
	(umask 022 ; $(srcdir)/mkinstalldirs $(DESTDIR)$(PRIVSEP_PATH))
	$(INSTALL) -m 0644 passwd_config $(DESTDIR)$(sysconfdir)/freesvr_passwd_config

	$(srcdir)/mkinstalldirs $(DESTDIR)$(logdir)
	
	$(srcdir)/mkinstalldirs $(DESTDIR)$(tmpdir)

uninstall:
	-rm -f $(DESTDIR)$(sbindir)/$(target)

