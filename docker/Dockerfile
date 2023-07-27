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
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
