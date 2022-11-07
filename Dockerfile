FROM golang
WORKDIR /app
COPY Makefile LICENSE go.mod go.sum main.go ./
COPY .git/ .git/
COPY cmd/ cmd/
COPY internal/ internal/
RUN make build
COPY bin/test-auth/build build/
CMD [ "bin/auth-server" ]
