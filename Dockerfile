FROM golang:1.25.1

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

RUN --mount=type=cache,target=/go/pkg/mod go mod download

ENV GOCACHE=/root/.cache/go-build

COPY . .
RUN go build -v -o /waf main.go

CMD ["/waf"]