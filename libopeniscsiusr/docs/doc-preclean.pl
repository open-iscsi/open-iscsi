#!/usr/bin/perl
# Copyright (C) 2016 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Gris Ge <fge@redhat.com>

use strict;

my @REMOVE_KEY_LIST=("__DLL_EXPORT");

while (<>) {
    for my $key (@REMOVE_KEY_LIST) {
        (s/$key//g);
    }
    print;
}
