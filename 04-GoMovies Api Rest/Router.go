/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        11/09/2019
*    @description Here we have all related for the Router.
 */

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Our Route model
type Route struct {
	Name       string
	Method     string
	Pattern    string
	HandleFunc http.HandlerFunc
}

// Array to store all routes
type Routes []Route

// Generating a router object and return it
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandleFunc)
	}
	return router
}

// Our Routes with callback fuctions
var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},
	Route{
		"Movies",
		"GET",
		"/movies",
		MoviesList,
	},
	Route{
		"Movie",
		"GET",
		"/movie/{name}",
		MovieShow,
	},
	Route{
		"AddMovie",
		"POST",
		"/addmovie",
		AddMovie,
	},
	Route{
		"UpdateMovie",
		"PUT",
		"/updatemovie/{name}",
		UpdateMovie,
	},
	Route{
		"DeleteMovie",
		"DELETE",
		"/deletemovie/{name}",
		DeleteMovie,
	},
}
