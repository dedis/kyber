package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
)

// creates a context to be used in the tests
func GenerateTestContext(suite Suite, c, s int) ([]Client, []Server, *AuthenticationContext, error) {
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", c) // ...
	}

	if s <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", s)
	}

	//Generates s servers
	serverKeys := make([]kyber.Point, 0, s)
	servers := make([]Server, 0, s)
	for i := 0; i < s; i++ {
		new, _ := NewServer(suite, i, nil)
		serverKeys = append(serverKeys, new.PublicKey())
		servers = append(servers, new)
	}

	//Generates the per-round secrets for the ServerSignature and keep track of the commits
	perRoundSecretCommits := make([]kyber.Point, 0, s)
	for i, serv := range servers {
		R, server := GenerateNewRoundSecret(suite, serv)
		perRoundSecretCommits = append(perRoundSecretCommits, R)
		servers[i] = server
	}

	//Generates c clients with their per-round generators
	clientKeys := make([]kyber.Point, 0, c)
	clients := make([]Client, 0, c)
	clientGenerators := make([]kyber.Point, 0, c)
	for i := 0; i < c; i++ {
		new, _ := NewClient(suite, i, nil)

		clientKeys = append(clientKeys, new.PublicKey())
		clients = append(clients, new)

		generator, err := GenerateClientGenerator(suite, i, perRoundSecretCommits)
		if err != nil {
			return nil, nil, nil, errors.New("error while generating client's generators:\n" + err.Error())
		}
		clientGenerators = append(clientGenerators, generator)
	}

	if context, err := NewAuthenticationContext(clientKeys, serverKeys, perRoundSecretCommits, clientGenerators); err != nil {
		return nil, nil, nil, errors.New("failed to create AuthenticationContext: " + err.Error())
	} else {
		return clients, servers, context, nil
	}
}
