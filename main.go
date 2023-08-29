package main

import (
	"fmt"
	"os"

	"github.com/takumakume/kev-to-dependencytrack/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
