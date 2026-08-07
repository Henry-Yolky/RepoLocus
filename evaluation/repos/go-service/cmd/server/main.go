package main

import (
	"fmt"
	"fixture.local/service/internal/health"
)

func main() {
	fmt.Println(health.ReadyStatus())
}
