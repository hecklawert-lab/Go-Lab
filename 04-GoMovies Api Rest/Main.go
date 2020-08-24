/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        11/09/2019
*    @description GoMovies is an API-REST developed in GoLang+MongoDB.
*				  For more information please see the README.md
 */

package main

import (
	"log"
	"net/http"
)

func main() {
	// Define our router object
	router := NewRouter()

	// Getting up the server
	server := http.ListenAndServe(":8080", router)
	log.Fatal(server)
}
