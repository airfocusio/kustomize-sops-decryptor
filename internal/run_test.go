package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

func TestReplace(t *testing.T) {
	// ageKeyPub1 := "age1ks0a8wkcdt74jp9l2chgny8e2pnjqta7rdwam4ju4ceqervn5ulq26q0wf"
	ageKeyPriv1 := "AGE-SECRET-KEY-1ZG7DTP6CK848WNETJZU6LT83DD6EVR9SJ32Y3CT7EZEUP7YFH0NQE2HPA4"
	// ageKeyPub2 := "age159rjxpjp0f3n075y26va9tyh22cmkykgm9gdegstx6887khtrewqrwayj8"
	ageKeyPriv2 := "AGE-SECRET-KEY-1P3XZ6S96208N9FVJUC6DQMR8M23EZ8AQ9400F0GH2E428G54EA9SNKA9CX"

	testCases := []struct {
		config Config
		input  string
		output string
		label  string
		error  error
	}{
		{
			config: Config{
				Age: ConfigAge{
					Keys: []string{},
				},
			},
			input: `apiVersion: v1
kind: Secret
metadata:
  name: secret
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: "1"
stringData:
  foo: ENC[AES256_GCM,data:5Czb,iv:9pu0tjIJz5plxRZ0XAs1DJCZcO/vOdQWavPmrX1xOb8=,tag:/QYxcDIvpVKhHCltEAAtPA==,type:str]
sops:
  kms: []
  gcp_kms: []
  azure_kv: []
  hc_vault: []
  age:
    - recipient: age1ks0a8wkcdt74jp9l2chgny8e2pnjqta7rdwam4ju4ceqervn5ulq26q0wf
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBucFBjTmZVaGtIeDlUay9r
        RkpCaFpRNkZXVkI1NnVBMTFRK2E0RTh2RVNnCjE3TVljWlJ5ckVsUVpFQ3BTaE9B
        QWlUNGpZeUszWEtsS2VmM2NWeFBxbWMKLS0tIDFVL1JCWnlKWi9SL3RSamgxZDln
        QVNhbnBQZFhTMjMwbC9WM1o1Q09oZzgK1n/KJheKDMFu+bStbiyR5oG0uxoJ0Wv7
        q7lENLefcYv6aVlq6A5T3+ixA3D7D+lGXfsmrWWVxdxkW6T4eeGFFw==
        -----END AGE ENCRYPTED FILE-----
  lastmodified: "2021-12-16T09:40:57Z"
  mac: ENC[AES256_GCM,data:04fF153myOIWX16XTqMR6q+BAxvKMXPI9nYsISzgvt6gimtUR/WWFjKq+Zi8WXKAXEd3iVI7xnC/9oPchi1th9DSWEyN3CejaTmb3uJmzBNdoAhDMlvVYeVgbYxq7dJ+d8widf+RWiCw0DxmwZGgiLX+KcOHOrwklN0K+Mc7G8s=,iv:bgepgqlGEk4rQgArq1/Qois29qQu4/QztlPsK1n3QRA=,tag:oxJ3GjtZiRhErZUS5DYmfQ==,type:str]
  pgp: []
  encrypted_regex: ^(data|stringData)$
  version: 3.7.1
`,
			output: `apiVersion: v1
kind: Secret
metadata:
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: '1'
    internal.config.kubernetes.io/index: '1'
    internal.config.kubernetes.io/id: '2'
    config.k8s.io/id: '2'
  name: encrypted
stringData:
  foo: ENC[AES256_GCM,data:5Czb,iv:9pu0tjIJz5plxRZ0XAs1DJCZcO/vOdQWavPmrX1xOb8=,tag:/QYxcDIvpVKhHCltEAAtPA==,type:str]
`,
			label: "no-key",
			error: fmt.Errorf("at least one key is needed"),
		},
		{
			config: Config{
				Age: ConfigAge{
					Keys: []string{ageKeyPriv1},
				},
			},
			input: `apiVersion: v1
kind: Secret
metadata:
  name: secret
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: "1"
stringData:
  foo: ENC[AES256_GCM,data:5Czb,iv:9pu0tjIJz5plxRZ0XAs1DJCZcO/vOdQWavPmrX1xOb8=,tag:/QYxcDIvpVKhHCltEAAtPA==,type:str]
sops:
  kms: []
  gcp_kms: []
  azure_kv: []
  hc_vault: []
  age:
    - recipient: age1ks0a8wkcdt74jp9l2chgny8e2pnjqta7rdwam4ju4ceqervn5ulq26q0wf
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBucFBjTmZVaGtIeDlUay9r
        RkpCaFpRNkZXVkI1NnVBMTFRK2E0RTh2RVNnCjE3TVljWlJ5ckVsUVpFQ3BTaE9B
        QWlUNGpZeUszWEtsS2VmM2NWeFBxbWMKLS0tIDFVL1JCWnlKWi9SL3RSamgxZDln
        QVNhbnBQZFhTMjMwbC9WM1o1Q09oZzgK1n/KJheKDMFu+bStbiyR5oG0uxoJ0Wv7
        q7lENLefcYv6aVlq6A5T3+ixA3D7D+lGXfsmrWWVxdxkW6T4eeGFFw==
        -----END AGE ENCRYPTED FILE-----
  lastmodified: "2021-12-16T09:40:57Z"
  mac: ENC[AES256_GCM,data:04fF153myOIWX16XTqMR6q+BAxvKMXPI9nYsISzgvt6gimtUR/WWFjKq+Zi8WXKAXEd3iVI7xnC/9oPchi1th9DSWEyN3CejaTmb3uJmzBNdoAhDMlvVYeVgbYxq7dJ+d8widf+RWiCw0DxmwZGgiLX+KcOHOrwklN0K+Mc7G8s=,iv:bgepgqlGEk4rQgArq1/Qois29qQu4/QztlPsK1n3QRA=,tag:oxJ3GjtZiRhErZUS5DYmfQ==,type:str]
  pgp: []
  encrypted_regex: ^(data|stringData)$
  version: 3.7.1
`,
			output: `apiVersion: v1
kind: Secret
metadata:
  name: secret
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: "1"
stringData:
  foo: bar
`,
			label: "works",
		},
		{
			config: Config{
				Age: ConfigAge{
					Keys: []string{ageKeyPriv2},
				},
			},
			input: `apiVersion: v1
kind: Secret
metadata:
  name: secret
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: "1"
stringData:
  foo: ENC[AES256_GCM,data:5Czb,iv:9pu0tjIJz5plxRZ0XAs1DJCZcO/vOdQWavPmrX1xOb8=,tag:/QYxcDIvpVKhHCltEAAtPA==,type:str]
sops:
  kms: []
  gcp_kms: []
  azure_kv: []
  hc_vault: []
  age:
    - recipient: age1ks0a8wkcdt74jp9l2chgny8e2pnjqta7rdwam4ju4ceqervn5ulq26q0wf
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBucFBjTmZVaGtIeDlUay9r
        RkpCaFpRNkZXVkI1NnVBMTFRK2E0RTh2RVNnCjE3TVljWlJ5ckVsUVpFQ3BTaE9B
        QWlUNGpZeUszWEtsS2VmM2NWeFBxbWMKLS0tIDFVL1JCWnlKWi9SL3RSamgxZDln
        QVNhbnBQZFhTMjMwbC9WM1o1Q09oZzgK1n/KJheKDMFu+bStbiyR5oG0uxoJ0Wv7
        q7lENLefcYv6aVlq6A5T3+ixA3D7D+lGXfsmrWWVxdxkW6T4eeGFFw==
        -----END AGE ENCRYPTED FILE-----
  lastmodified: "2021-12-16T09:40:57Z"
  mac: ENC[AES256_GCM,data:04fF153myOIWX16XTqMR6q+BAxvKMXPI9nYsISzgvt6gimtUR/WWFjKq+Zi8WXKAXEd3iVI7xnC/9oPchi1th9DSWEyN3CejaTmb3uJmzBNdoAhDMlvVYeVgbYxq7dJ+d8widf+RWiCw0DxmwZGgiLX+KcOHOrwklN0K+Mc7G8s=,iv:bgepgqlGEk4rQgArq1/Qois29qQu4/QztlPsK1n3QRA=,tag:oxJ3GjtZiRhErZUS5DYmfQ==,type:str]
  pgp: []
  encrypted_regex: ^(data|stringData)$
  version: 3.7.1
`,
			output: `apiVersion: v1
kind: Secret
metadata:
  annotations:
    some.domain.com/foo: bar
    config.kubernetes.io/index: '1'
    internal.config.kubernetes.io/index: '1'
    internal.config.kubernetes.io/id: '2'
    config.k8s.io/id: '2'
  name: encrypted
stringData:
  foo: ENC[AES256_GCM,data:5Czb,iv:9pu0tjIJz5plxRZ0XAs1DJCZcO/vOdQWavPmrX1xOb8=,tag:/QYxcDIvpVKhHCltEAAtPA==,type:str]
`,
			label: "wrong-key",
			error: fmt.Errorf("Error getting data key: 0 successful groups required, got 0"),
		},
	}

	for _, testCase := range testCases {
		inputYaml := yaml.Node{}
		if assert.NoError(t, yaml.Unmarshal([]byte(testCase.input), &inputYaml), testCase.label) {
			outputNodes, err := decrypt(&testCase.config)([]*yaml.RNode{yaml.NewRNode(&inputYaml)})
			if testCase.error != nil {
				assert.EqualError(t, err, testCase.error.Error(), testCase.label, testCase.label)
			} else if assert.NoError(t, err, testCase.label) {
				if assert.Equal(t, 1, len(outputNodes), testCase.label) {
					outputBytes, err := yaml.Marshal(outputNodes[0].YNode())
					if assert.NoError(t, err, testCase.label) {
						output := string(outputBytes)
						assert.Equal(t, testCase.output, output, testCase.label)
					}
				}
			}
		}
	}
}
