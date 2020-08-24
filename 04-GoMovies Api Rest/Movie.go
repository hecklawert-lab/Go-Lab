/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        11/09/2019
*    @description Just a Movie data model made with a Struct
 */

package main

// Our Json Model
type Movie struct {
	Name     string `json:"name"`
	Year     int    `json:"year"`
	Director string `json:"director"`
}

type Movies []Movie
