/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        09/09/2019
*    @description Some looping exercises in GoLang
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

	// Range iterator
	for k, v := range statePopulation {
		fmt.Printf("CITY: %s     POPULATION: %d\n", k, v)
	}

	for _, v := range statePopulation {
		fmt.Println(v)
	}
}
