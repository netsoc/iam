FROM golang:1.15-alpine AS builder

WORKDIR /usr/local/lib/iamd
COPY go.* ./
RUN go mod download

COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN mkdir bin/ && CGO_ENABLED=0 go build -o bin/ ./cmd/...


FROM alpine:3.12

COPY --from=builder /usr/local/lib/iamd/bin/* /usr/local/bin/

EXPOSE 80/tcp
ENTRYPOINT ["/usr/local/bin/iamd"]
