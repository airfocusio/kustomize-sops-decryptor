# kustomize-sops-transformer

Plugin for [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) to allow on-the-fly decryption with [sops](https://github.com/mozilla/sops).

Note: Only [age](https://github.com/FiloSottile/age) is supported!

## Usage

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: secret
stringData:
  foo: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  age:
    - recipient: ...
      enc: ...
  version: 3.7.1

# decryptor.yaml
kind: SopsDecryptor
metadata:
  name: sops-decryptor
  annotations:
    config.kubernetes.io/function: |
      container:
        image: ghcr.io/choffmeister/kustomize-sops-transformer:latest
age:
  keys:
    - AGE-SECRET-KEY-...

# kustomization.yaml
resources:
  - secret.yaml
transformers:
  - decryptor.yaml
```

## Caveats

Plugins are still in alpha. For this to work, you need to provide the `--enable-alpha-plugins` flag (i.e. `kustomize build --enable-alpha-plugins`).

So far there is no way for kustomize (container) plugins to consume environment variables at runtime. So you have to inject the secret into the `decryptor.yaml` file and make sure, that you don't accidentially commit it. For example the continous deployment job could do that.
