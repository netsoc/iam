FROM golang:1.16-alpine3.14 AS builder

WORKDIR /usr/local/lib/iamd
COPY go.* ./
RUN go mod download

COPY tools.go ./
RUN cat tools.go | sed -nr 's|^\t_ "(.+)"$|\1|p' | xargs -tI % go get %

COPY static/ ./static/
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN mkdir -p internal/data && go-bindata -fs -o internal/data/bindata.go -pkg data -prefix static/ static/...
RUN mkdir bin/ && CGO_ENABLED=0 go build -o bin/ ./cmd/...


FROM alpine:3.14

COPY --from=builder /usr/local/lib/iamd/bin/* /usr/local/bin/

EXPOSE 80/tcp
ENTRYPOINT ["/usr/local/bin/iamd"]

LABEL org.opencontainers.image.source https://github.com/netsoc/iam
