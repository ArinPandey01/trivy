FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags='-s -w' -o /out/trivy-api ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/trivy-api /trivy-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/trivy-api"]
