# ===========
# Build stage
# ===========
FROM golang:alpine AS builder

WORKDIR /code

# Pre-install dependencies to cache them as a separate image layer
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . /code
RUN go build -o certificator ./cmd/certificator

# ===========
# Final stage
# ===========
FROM alpine:latest

WORKDIR /app
RUN apk --no-cache add curl

COPY ./fixtures /app/fixtures
COPY ./domains.yml /app/fixtures/domains.yml

COPY --from=builder /code/certificator .

CMD [ "./certificator" ]
