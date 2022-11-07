package main

import (
	"github.com/konveyor/auth-server/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	if err := cmd.SetupCobraAndRun(); err != nil {
		logrus.Fatal(err)
	}
}
