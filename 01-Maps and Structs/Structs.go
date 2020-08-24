/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        08/09/2019
*    @description Struct data in GoLang
 */

package main

import "fmt"

type Doctor struct {
	number     int
	actorName  string
	companions []string
}

func main() {
	aDoctor := Doctor{
		number:    3,
		actorName: "Jon Pertwee",
		companions: []string{
			"Liz Shaw",
			"Jo Grant",
			"Sarah Jane Smith",
		},
	}
	fmt.Println(aDoctor)
}
