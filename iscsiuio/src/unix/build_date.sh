#!/bin/bash
#
# build the build_date.c and build_date.h files
#
# (bash required for getopts)
#

THIS_CMD=${0##*/}

usage()
{
    echo "Usage: $THIS_CMD [OPTIONS]"
    echo "Where OPTIONS are from:"
    echo "  -c OUT_SOURCE         create C source file OUT_SOURCE with the date"
    echo "  -i OUT_HEADER         create C include file OUT_HEADER for the date file"
    echo "  -S EPOCH_DATE_NUMBER  use '--date=@EPOCH_DATE_NUMBER' to set date (repeatable builds)"
    echo "Also sets EPOCH date number from SOURCE_DATE_EPOCH if set in the environment"
}

generate_source_file()
{
    outfile="$1"
    if [ -n "$SOURCE_DATE_EPOCH" ] ; then
	echo 'char *build_date = "'`LC_ALL=C.UTF-8 date --date=@$SOURCE_DATE_EPOCH -u`'";' >"$outfile"
    else
	echo 'char *build_date = "'`date`'";' >"$outfile"
    fi
}

generate_include_file()
{
    outfile="$1"
    echo 'extern char *build_date;' >"$outfile"
}

do_source=
do_include=

while getopts :c:i:S:h opt; do
    case "$opt" in
    c) do_source="$OPTARG" ;;
    i) do_include="$OPTARG" ;;
    S) SOURCE_DATE_EPOCH="$OPTARG" ;;
    h) usage; exit 0 ;;
    ?) echo "unknown option" 1>&2; usage; exit 1 ;; 
    esac
done

if [ -n "$do_source" ]; then
   generate_source_file $do_source
fi
if [ -n "$do_include" ]; then
    generate_include_file $do_include
fi
