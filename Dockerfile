FROM golang:1.20

WORKDIR /app

COPY . .

WORKDIR /app/cmd

RUN go build -o main .

CMD ["./main"]