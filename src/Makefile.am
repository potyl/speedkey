bin_PROGRAMS      = speedkey
speedkey_SOURCES  = speedkey.c


if HAS_OPENSSL
speedkey_CPPFLAGS = -DHAS_OPENSSL
speedkey_LDADD    = @OPENSSL_LIBS@
else
speedkey_CPPFLAGS = -I$(top_srcdir)/sha1
speedkey_LDADD    = $(top_srcdir)/sha1/libsha1.a
endif
