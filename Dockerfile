FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /zkettle .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /zkettle /usr/local/bin/zkettle
RUN adduser -D -u 10001 zkettle && mkdir -p /data && chown zkettle:zkettle /data
USER zkettle
EXPOSE 3000
VOLUME /data
ENTRYPOINT ["zkettle"]
CMD ["mcp", "--host", "0.0.0.0", "--port", "3000", "--data", "/data"]
