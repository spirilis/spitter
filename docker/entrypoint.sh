#!/bin/sh

case "$1" in
    router)
        # Router default port is 9820
        shift
        ARGS="$@"
        if [ -n "$CONFIG_FILE" ]; then
            ARGS="$ARGS --config=${CONFIG_FILE}"
        elif [ -n "$CONFIG" ]; then
            # Submitting the config as a one-liner is probably easier if it's encoded as JSON
            cat <<EOF > /tmp/config.yml
${CONFIG}
EOF
            ARGS="$ARGS --config=/tmp/config.yml"
        fi
        if [ -n "$ALERTMANAGER_URL" ]; then
            ARGS="$ARGS --alertmanager=${ALERTMANAGER_URL}"
        fi
        if [ -n "$PROMETHEUS_URL" ]; then
            ARGS="$ARGS --prometheus=${PROMETHEUS_URL}"
        fi
        if [ -n "$ROUTERS_DIR" ]; then
            ARGS="$ARGS --routers=${ROUTERS_DIR}"
        fi

        /usr/local/bin/spitter router $ARGS
        ;;
    dump)
        shift
        ARGS="$@"
        if [ -n "$PORT" ]; then
            ARGS="$ARGS --port=${PORT}"
        fi

        /usr/local/bin/spitter dump $ARGS
        ;;
    *)
        shift
        $0 router "$@"
        ;;
esac
