FROM alpine:latest as certs
RUN apk add --update --no-cache ca-certificates
COPY kustomize-sops-decryptor /bin/kustomize-sops-decryptor
ENTRYPOINT ["/bin/kustomize-sops-decryptor"]
WORKDIR /workdir
