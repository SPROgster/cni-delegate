package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestMulti(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "multi")
}
