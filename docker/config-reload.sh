#!/bin/sh

if [ -z "$2" ]; then
    echo "Syntax: $0 <directory to watch> <triggerfile to create>"
    echo "  This tool watches for changes in the specified directory (\$1) and will touch a 0-length triggerfile when the"
    echo "  contents change.  This is intended to inform the spitter webhook router to reload its router configs in response"
    echo "  to the directory contents (presumed to be the set of router configs) changing."
    exit 1
fi

WATCH_DIR="$1"
TRIGGERFILE="$2"

function sum_files() {
    cd $WATCH_DIR
    cat * | sha256sum | awk '{print $1}'
}

CHECKSUM="$(sum_files)"

while [ 1 ]; do
    sleep 5
    NEWSUM="$(sum_files)"
    if [ "$NEWSUM" != "$CHECKSUM" ]; then
        touch "$TRIGGERFILE"
        CHECKSUM="$NEWSUM"
    fi
done
