package internal

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
	"sigs.k8s.io/kustomize/kyaml/kio"
	"sigs.k8s.io/kustomize/kyaml/yaml"

	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/decrypt"
)

type Config struct {
	Age struct {
		Keys []string `yaml:"keys"`
	} `yaml:"age"`
}

func Run() error {
	injectedAnnotations := []string{
		"config.k8s.io/id",
		"config.kubernetes.io/index",
		"internal.config.kubernetes.io/id",
		"internal.config.kubernetes.io/index",
		"kustomize.config.k8s.io/id",
	}

	config := new(Config)
	fn := func(items []*yaml.RNode) ([]*yaml.RNode, error) {
		if len(config.Age.Keys) == 0 {
			return nil, fmt.Errorf("age.keys needs at least one key")
		}
		keyFile, err := ioutil.TempFile("", "agekey-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(keyFile.Name())
		keyFileContent := strings.Join(config.Age.Keys, "\n") + "\n"
		err = ioutil.WriteFile(keyFile.Name(), []byte(keyFileContent), 0o600)
		if err != nil {
			return nil, err
		}
		// TODO find programmatic way
		os.Setenv("SOPS_AGE_KEY_FILE", keyFile.Name())

		for i := range items {
			if items[i].Field("sops") != nil {
				for _, kustomizeAnnotation := range injectedAnnotations {
					items[i].PipeE(yaml.ClearAnnotation(kustomizeAnnotation))
				}
				yamlIn := items[i].YNode()
				bytesIn, err := yaml.Marshal(yamlIn)
				if err != nil {
					return nil, err
				}

				bytesOut, err := decrypt.DataWithFormat(bytesIn, formats.Yaml)
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

	p := framework.SimpleProcessor{Config: config, Filter: kio.FilterFunc(fn)}
	cmd := command.Build(p, command.StandaloneDisabled, false)
	err := cmd.Execute()
	if err != nil {
		os.Stderr.WriteString("\n")
		return err
	}
	return nil
}
