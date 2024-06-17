package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/hello", helloHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/insecure", insecureHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Starting server at port 80801")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the Home Page!")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}
	// Уязвимость XSS
	fmt.Fprintf(w, "Hello, %s!", name)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.ServeFile(w, r, "upload.html")
		return
	}

	file, header, err := r.FormFile("uploadfile")
	if err != nil {
		http.Error(w, "File upload error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	filename := header.Filename

	// Пользовательский ввод в названии директории
	out, err := os.Create("/tmp/" + filename)
	if err != nil {
		http.Error(w, "Unable to create the file for writing. Check your write access privilege", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, "File copy error", http.StatusInternalServerError)
		return
	}

	// Использование устаревшего хэш-алгоритма
	hash := md5.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		http.Error(w, "Hashing error", http.StatusInternalServerError)
		return
	}

	// Прямое использование пользовательского ввода
	token := r.FormValue("token")
	fmt.Fprintf(w, "Token: %s", token)

	fmt.Fprintf(w, "File uploaded successfully")
}

func insecureHandler(w http.ResponseWriter, r *http.Request) {
	// Генерация предсказуемых токенов
	token := generatePredictableToken()
	fmt.Fprintf(w, "Your token is: %s", token)

	// Использование устаревшего хэш-алгоритма
	hash := sha1.New()
	io.WriteString(hash, "password")
	fmt.Fprintf(w, "SHA1 hash of 'password': %x", hash.Sum(nil))

	// Неправильное управление базой данных
	databaseURL := r.URL.Query().Get("db")
	fmt.Fprintf(w, "Connecting to database at %s", databaseURL)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if validateUser(username, password) {
			fmt.Fprintf(w, "Welcome, %s!", username)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	} else {
		http.ServeFile(w, r, "login.html")
	}
}

func validateUser(username, password string) bool {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		return false
	}
	defer db.Close()

	// SQL-инъекция
	//query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	rows, err := db.Query("SELECT * FROM users WHERE username=? AND password=?", username, password)
	if err != nil {
		return false
	}
	defer rows.Close()

	return rows.Next()
}

func generatePredictableToken() string {
	// Генерация предсказуемого токена
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
