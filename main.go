package main

import (
	"fmt"
	"github.com/devops-kung-fu/go-shs/api"
)

func main() {
	shs := api.NewAPI(api.DefaultConfig())
	score := shs.CalculateVectors([]string{"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"})
	fmt.Println(score)
}
