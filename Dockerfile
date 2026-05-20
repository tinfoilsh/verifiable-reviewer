FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o verifiable-reviewer .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/verifiable-reviewer /verifiable-reviewer

EXPOSE 8080

ENTRYPOINT ["/verifiable-reviewer"]
