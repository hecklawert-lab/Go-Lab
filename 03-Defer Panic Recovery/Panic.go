/*
*    @author      Hëck Lawert
*    @githuh      https://github.com/hecklawert
*    @date        09/09/2019
*    @description Panic example in GoLang
 */

package main

import "net/http"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world"))
	})
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err.Error())
	}
}
