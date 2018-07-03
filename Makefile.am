#
#   This file is part of Sylverant PSO Server.
#
#   Copyright (C) 2009, 2014, 2018 Lawrence Sebald
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

LIBS += $(MYSQL_LIBS) $(LIBICONV)

bin_PROGRAMS = shipgate
shipgate_SOURCES = src/packets.c src/ship.c src/ship.h src/ship_packets.h \
                   src/shipgate.c src/shipgate.h

if NEED_PIDFILE
AM_CFLAGS = -DNEED_PIDFILE=1
shipgate_SOURCES += src/pidfile.c
endif

datarootdir = @datarootdir@
