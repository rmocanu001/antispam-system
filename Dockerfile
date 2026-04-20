FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /antispam ./cmd/antispam
RUN go build -o /policyservice ./cmd/policyservice
RUN go build -o /contentfilter ./cmd/contentfilter
RUN go build -o /benchmark ./cmd/benchmark

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=build /antispam /usr/local/bin/antispam
COPY --from=build /policyservice /usr/local/bin/policyservice
COPY --from=build /contentfilter /usr/local/bin/contentfilter
COPY --from=build /benchmark /usr/local/bin/benchmark
COPY samples/ /data/samples/

WORKDIR /data

ENTRYPOINT ["antispam"]
