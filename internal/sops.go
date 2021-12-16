package internal

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	sopsAes "go.mozilla.org/sops/v3/aes"
	sopsCommon "go.mozilla.org/sops/v3/cmd/sops/common"
	sopsFormats "go.mozilla.org/sops/v3/cmd/sops/formats"
	sopsKeyservice "go.mozilla.org/sops/v3/keyservice"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func sopsAgeDecrypt(data []byte, format sopsFormats.Format, identities []age.Identity, ignoreMac bool) (cleartext []byte, err error) {
	store := sopsCommon.StoreForFormat(format)

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, err
	}

	key, err := tree.Metadata.GetDataKeyWithKeyServices([]sopsKeyservice.KeyServiceClient{
		sopsLocalAgeKeyServiceClient{
			Identities: identities,
		},
	})
	if err != nil {
		return nil, err
	}

	cipher := sopsAes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	if !ignoreMac {
		originalMac, _ := cipher.Decrypt(
			tree.Metadata.MessageAuthenticationCode,
			key,
			tree.Metadata.LastModified.Format(time.RFC3339),
		)
		if originalMac != mac {
			return nil, fmt.Errorf("failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
		}
	}

	return store.EmitPlainFile(tree.Branches)
}

type sopsLocalAgeKeyServiceClient struct {
	Identities []age.Identity
}

func (ks sopsLocalAgeKeyServiceClient) Encrypt(ctx context.Context, req *sopsKeyservice.EncryptRequest, opts ...grpc.CallOption) (*sopsKeyservice.EncryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Not implemented")
}
func (ks sopsLocalAgeKeyServiceClient) Decrypt(ctx context.Context, req *sopsKeyservice.DecryptRequest, opts ...grpc.CallOption) (*sopsKeyservice.DecryptResponse, error) {
	key := *req.Key
	var response *sopsKeyservice.DecryptResponse
	switch k := key.KeyType.(type) {
	case *sopsKeyservice.Key_AgeKey:
		plaintext, err := ks.decryptWithAge(k.AgeKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &sopsKeyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unsupported key type")
	}
	return response, nil
}

func (ks *sopsLocalAgeKeyServiceClient) decryptWithAge(key *sopsKeyservice.AgeKey, ciphertext []byte) ([]byte, error) {
	src := bytes.NewReader(ciphertext)
	ar := armor.NewReader(src)

	r, err := age.Decrypt(ar, ks.Identities...)
	if err != nil {
		return nil, fmt.Errorf("no age identity found that could decrypt the data: %w", err)
	}

	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return nil, fmt.Errorf("failed to copy decrypted data into bytes.Buffer: %w", err)
	}

	return b.Bytes(), nil
}
