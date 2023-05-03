package main

import (
	"html/template"
	"log"
	"net/http"
)


// Serve measure.html or latency.html on localhost:8080 to make local frontend dev easier
func main() {
	http.HandleFunc("/", servePage)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func servePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/latency.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}