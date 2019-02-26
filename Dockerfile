FROM golang:1.22-alpine AS builder

# Copy code
WORKDIR /app
COPY . .

# Add ca certificates
RUN apk add --no-cache git

# Fetch dependencies
RUN go mod download
RUN go mod verify

# Build the binary
RUN GOOS=linux GOARCH=amd64 go build -o watchsumo-checker

# Build production image
# When updating, make sure this version matches what alpine is used in the
# builder image
FROM alpine:3.19

# Add ca certificates
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Create appuser
ENV USER=appuser
ENV UID=10001
RUN adduser \    
    --disabled-password \    
    --gecos "" \    
    --home "/nonexistent" \    
    --shell "/sbin/nologin" \    
    --no-create-home \    
    --uid "${UID}" \    
    "${USER}"

# Copy our static executable
COPY --from=builder /app/watchsumo-checker /watchsumo-checker

# Run as an unprivileged user
USER appuser:appuser

# Run binary
CMD ["/watchsumo-checker", "start"]
