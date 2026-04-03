FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /plexar .

# Trivy binary — bundled so users get CVE scanning out of the box
FROM aquasec/trivy:latest AS trivy

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /plexar /usr/local/bin/plexar
USER 65534:65534
ENTRYPOINT ["plexar"]
CMD ["serve", "--bind=0.0.0.0"]
