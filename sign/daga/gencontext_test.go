package daga

import (
	"github.com/dedis/kyber"
	"math/rand"
	"testing"
)

// TODO WTF ^^ now lack a testtestGenerateTestContext
func TestGenerateTestContext(t *testing.T) {
	//Randomly choses the number of clients and servers in [1,10]
	c := rand.Intn(10) + 1
	s := rand.Intn(10) + 1
	clients, servers, context, err := GenerateTestContext(suite, c, s)

	if err != nil || clients == nil || servers == nil || context == nil {
		t.Error("Impossible to generate context")
	}

	//Testing lengths
	if len(clients) != c {
		t.Error("Wrong clients length")
	}

	if len(context.h) != c {
		t.Error("Wrong H length")
	}

	if len(context.g.x) != c {
		t.Error("Wrong X length")
	}

	if len(servers) != s {
		t.Error("Wrong servers length")
	}

	if len(context.r) != s {
		t.Error("Wrong R length")
	}

	if len(context.g.y) != s {
		t.Error("Wrong Y length")
	}

	//Testing invalid values
	a, b, d, err := GenerateTestContext(suite, 0, s)
	if a != nil || b != nil || d != nil || err == nil {
		t.Error("Wrong handling of 0 clients")
	}

	a, b, d, err = GenerateTestContext(suite, c, 0)
	if a != nil || b != nil || d != nil || err == nil {
		t.Error("Wrong handling of 0 servers")
	}

	neg := -rand.Int()
	a, b, d, err = GenerateTestContext(suite, neg, s)
	if a != nil || b != nil || d != nil || err == nil {
		t.Errorf("Wrong handling of negative clients: %d", neg)
	}

	a, b, d, err = GenerateTestContext(suite, c, neg)
	if a != nil || b != nil || d != nil || err == nil {
		t.Errorf("Wrong handling of negative servers: %d", neg)
	}

	if servers[0].RoundSecret() == nil {
		t.Error("Error in generation of r")
	}
	if servers[0].PrivateKey() == nil {
		t.Error("Error in generation of private")
	}

}

func TestGenerateClientGenerator(t *testing.T) {
	//Test correct execution of the function
	index := rand.Int()
	var commits []kyber.Point
	for i := 0; i < rand.Intn(10)+1; i++ {
		commits = append(commits, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	}
	h, err := GenerateClientGenerator(suite, index, commits)
	if err != nil || h == nil {
		t.Errorf("Cannot generate generator with index: %d", index)
	}
	h, err = GenerateClientGenerator(suite, 0, commits)
	if err != nil || h == nil {
		t.Error("Cannot generate generator with index 0")
	}

	//Test wrong execution of the function
	neg := -rand.Int()
	h, err = GenerateClientGenerator(suite, neg, commits)
	if h != nil || err == nil {
		t.Errorf("Error in handling negative index: %d", index)
	}

	h, err = GenerateClientGenerator(suite, index, []kyber.Point{})
	if h != nil || err == nil {
		t.Errorf("Error in handling empty commits")
	}

}
