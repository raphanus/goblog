package main

import "github.com/raphanus/goblog/cmd/goblog/cmd"

var version string // set by the compiler

func main() {
	cmd.Execute(version)
}
