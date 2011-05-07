#!/bin/sh

# In OS X the ports system installs the aclocal macro in a different location
includes=
if [ -e /opt/local/share/aclocal ]; then
	includes="-I /opt/local/share/aclocal $includes"
fi

if [ -e /usr/local/share/aclocal ]; then
	includes="-I /usr/local/share/aclocal $includes"
fi


aclocal $includes --force
autoconf --force
autoheader --force
automake --add-missing --copy --force-missing
