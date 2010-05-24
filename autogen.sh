#!/bin/sh

aclocal --force
autoconf --force
autoheader --force
automake --add-missing --copy --force-missing
