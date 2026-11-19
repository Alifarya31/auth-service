# Tahap build: kompilasi binary statis.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-service ./cmd/server

# Tahap runtime: image minimal tanpa shell, berjalan sebagai user non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth-service /auth-service
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/auth-service"]
