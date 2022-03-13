FROM golang:1.18-rc-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go build -o frontier github.com/toshokan/frontier/cmd/frontier

FROM gcr.io/distroless/base-debian11
WORKDIR /app
COPY --from=builder /app/frontier .
CMD ["/app/frontier"]
