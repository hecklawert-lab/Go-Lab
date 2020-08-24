/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        11/09/2019
*    @description Here we have all the logic of the routes.
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"gopkg.in/mgo.v2/bson"
)

/*
***************************************
*									  *
*			HELPER METHODS			  *
*									  *
***************************************
 */

// Method to generate responses
func Response(w http.ResponseWriter, status int, responseData interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(responseData)
}

// Struct and methods to generate a JSON "Message"
type Message struct {
	Status  string `json:status`
	Message string `json:message`
}

func (this *Message) setMessage(argStatus string, argMessage string) {
	this.Status = argStatus
	this.Message = argMessage
}

func newMessage(argStatus string, argMessage string) *Message {
	message := new(Message)
	message.setMessage(argStatus, argMessage)
	return message
}

/*
***************************************
*									  *
*			     ROUTES			  	  *
*									  *
***************************************
 */

// Logic of Routes
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from our index page")
}
func MoviesList(w http.ResponseWriter, r *http.Request) {
	var results []Movie
	err := collection.Find(nil).All(&results)
	if err != nil {
		log.Fatal("Error trying to obtain data back from MongoDB")
	} else {
		log.Println(results)
	}

	Response(w, 200, results)
}
func MovieShow(w http.ResponseWriter, r *http.Request) {
	// Get params and store in a var
	params := mux.Vars(r)
	movie_name := params["name"]

	// Get a movie from database
	results := Movie{}
	err := collection.Find(bson.M{"name": movie_name}).One(&results)
	if err != nil {
		w.WriteHeader(404)
		return
	}

	// If everything is ok return 200 HTTP Response with our JSON
	Response(w, 200, results)
}
func AddMovie(w http.ResponseWriter, r *http.Request) {
	// Decode JSON Data
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var movie_data Movie

	err := decoder.Decode(&movie_data)
	if err != nil {
		panic(err)
	}

	// Insert data in MongoDB
	err = collection.Insert(movie_data)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	// Return HTTP Response
	Response(w, 200, movie_data)
}

func UpdateMovie(w http.ResponseWriter, r *http.Request) {
	// Get params and store in a var
	params := mux.Vars(r)
	movie_name := params["name"]

	// Handling our request data
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	var movie_data Movie
	err := decoder.Decode(&movie_data)
	if err != nil {
		panic(err)
		w.WriteHeader(500)
		return
	}

	err = collection.Update(bson.M{"name": movie_name}, bson.M{"$set": movie_data})
	if err != nil {
		w.WriteHeader(404)
		return
	}
	// If everything is ok return 200 HTTP Response with our JSON
	Response(w, 200, movie_data)
}
func DeleteMovie(w http.ResponseWriter, r *http.Request) {
	// Get params and store in a var
	params := mux.Vars(r)
	movie_name := params["name"]

	// Remove a movie from database
	err := collection.Remove(bson.M{"name": movie_name})
	if err != nil {
		w.WriteHeader(500)
		return
	}

	message := newMessage("success", "Film with name "+movie_name+" has ben erased.")
	Response(w, 200, message)

}
