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
    # intentionally ignoring any dot-files here
    cat * 2>/dev/null | sha256sum | awk '{print $1}'
}

CHECKSUM="$(sum_files)"

# $immediate_reloads is a sanity check to make sure we're not in a loop continuously requesting a reload
immediate_reloads="0"

while [ 1 ]; do
    sleep 5
    NEWSUM="$(sum_files)"
    if [ "$NEWSUM" != "$CHECKSUM" ]; then
        immediate_reloads="$(expr $immediate_reloads + 1)"
        touch "$TRIGGERFILE"
        CHECKSUM="$NEWSUM"
    else
        immediate_reloads="0"
    fi

    if [ "$immediate_reloads" -gt "3" ]; then
        echo "Something's up - we're in a continual reload request loop.  Exit 1 to crash the container"
        exit 1
    fi
done
