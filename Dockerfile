# Use a minimal base image for Go programs
FROM golang:1.22-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules files
COPY go.mod go.sum ./

# Download and install Go modules
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application
RUN go build -o umami-controller .

# Use a minimal base image for the final runtime
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the built executable from the builder stage
COPY --from=builder /app/umami-controller .

# Command to run the executable
CMD ["./umami-controller"]
