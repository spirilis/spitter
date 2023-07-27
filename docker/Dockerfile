FROM golang:1.20-alpine AS build

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o /spitter

FROM alpine:3.16 AS runtime

RUN apk update && apk add curl bash less

COPY --from=build /spitter /usr/local/bin/.

EXPOSE 9820

COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/config-reload.sh /usr/local/bin/.

RUN chmod 755 /entrypoint.sh /usr/local/bin/config-reload.sh

ENTRYPOINT ["/entrypoint.sh"]
