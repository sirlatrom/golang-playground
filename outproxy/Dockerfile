FROM        golang:alpine
RUN         apk add --update git
COPY        . /go/src/outproxy/
WORKDIR     /go/src/outproxy
RUN         go-wrapper download && go-wrapper install
CMD         go-wrapper run