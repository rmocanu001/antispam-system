FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o accountadmin .

# ---- runtime ----
FROM scratch
COPY --from=builder /app/accountadmin /accountadmin
EXPOSE 8081
ENTRYPOINT ["/accountadmin"]
