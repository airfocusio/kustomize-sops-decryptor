FROM alpine:latest as certs
RUN apk add --update --no-cache ca-certificates
COPY kustomize-sops-transformer /bin/kustomize-sops-transformer
ENTRYPOINT ["/bin/kustomize-sops-transformer"]
WORKDIR /workdir
