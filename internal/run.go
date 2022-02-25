package internal

import (
	"fmt"
	"os"

	"filippo.io/age"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
	"sigs.k8s.io/kustomize/kyaml/kio"
	"sigs.k8s.io/kustomize/kyaml/yaml"

	sopsFormats "go.mozilla.org/sops/v3/cmd/sops/formats"
)

type ConfigAge struct {
	Keys []string `yaml:"keys"`
}

type Config struct {
	Age ConfigAge `yaml:"age"`
}

func Run() error {
	config := new(Config)
	p := framework.SimpleProcessor{Config: config, Filter: kio.FilterFunc(decrypt(config))}
	cmd := command.Build(p, command.StandaloneDisabled, false)
	err := cmd.Execute()
	if err != nil {
		os.Stderr.WriteString("\n")
		return err
	}
	return nil
}

func decrypt(config *Config) func(items []*yaml.RNode) ([]*yaml.RNode, error) {
	return func(items []*yaml.RNode) ([]*yaml.RNode, error) {
		if len(config.Age.Keys) == 0 {
			return nil, fmt.Errorf("at least one key is needed")
		}

		identities := []age.Identity{}
		for _, identityStr := range config.Age.Keys {
			identity, err := age.ParseX25519Identity(identityStr)
			if err != nil {
				return nil, err
			}
			identities = append(identities, identity)
		}

		for i := range items {
			if items[i].Field("sops") != nil {
				yamlIn := items[i].YNode()
				bytesIn, err := yaml.Marshal(yamlIn)
				if err != nil {
					return nil, err
				}
				bytesOut, err := sopsAgeDecrypt(bytesIn, sopsFormats.Yaml, identities, true)
				if err != nil {
					return nil, err
				}
				yamlOut := yaml.Node{}
				err = yaml.Unmarshal(bytesOut, &yamlOut)
				if err != nil {
					return nil, err
				}
				items[i].SetYNode(&yamlOut)
			}
		}

		return items, nil
	}
}
