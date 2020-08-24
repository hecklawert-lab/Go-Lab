/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        08/09/2019
*    @description Maps in GoLang
 */

package main

import "fmt"

func main() {
	// Define our map with the population of some cities
	statePopulation := map[string]int{
		"Madrid":    2313345,
		"Bilbao":    1432659,
		"Barcelona": 2184254,
		"Logrono":   145931,
	}
	pop, ok := statePopulation["Logrono"] // Return our value and if exits
	fmt.Println(pop, ok)
	pop, ok = statePopulation["Valencia"] // Valencia key doesn't exist so ok var should be false
	fmt.Println(pop, ok)
}
