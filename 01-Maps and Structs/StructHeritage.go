/*

*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        08/09/2019
*    @description Struct heritage in GoLang

 */
package main

import "fmt"

type Animal struct {
	Name   string
	Origin string
}

type Bird struct {
	Animal
	SpeedKPH float32
	CanFly   bool
}

func main() {
	myBird := Bird{}
	myBird.Name = "Emu"
	myBird.Origin = "Australia"
	myBird.SpeedKPH = 48
	myBird.CanFly = true
	fmt.Println(myBird)
	fmt.Println("Name: ", myBird.Name)
}
