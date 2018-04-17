package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
)

const (
	dbhost = "DBHOST"
	dbport = "DBPORT"
	dbuser = "DBUSER"
	dbpass = "DBPASS"
	dbname = "DBNAME"
	url    = "http://localhost" //USED IN CONJUCTION WITH MAILGUN MAIL, CHANGE IN PRODUCTION
	k      = 30                 //How much of an effect each game will have
)

type challenge struct {
	Acceptor, Date, ID, Initiator, Winner, WinningString string
	Opponent                                             struct {
		Fname, Lname string
	}
}

type confirmData struct {
	Initiator   user
	Error       string
	Achallenges []challenge
	Ichallenges []challenge
	users
}

type templateData struct {
	Admin, Authenticated, Dual            bool
	Game, GameTitle, Theme, ThemeAlt      string
	ThemeHighlighter, ThemeHighlighterAlt string
	Data                                  interface{}
}

type locationalError struct {
	Error                 error
	Location, Sublocation string
}

type session struct {
	pid int16
	uid string
}

type user struct {
	Email, Fname, Lname, Password, UUID string
	ID, Score                           int16
}

type userAuth struct {
	Email, Fname, Lname, Password string
	ID, Score                     int16
}

type users struct {
	Users []user
}

var mg *mailgun.Mailgun
var errorChannel chan locationalError
var db *sql.DB
var tpl *template.Template

func init() {
	config := dbConfig()
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config[dbhost], config[dbport], config[dbuser], config[dbpass], config[dbname],
	)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println(fmt.Sprintf("Successfully connected to the %s database!", config[dbname]))
}

func main() {
	errorChannel = make(chan locationalError)

	go errorDrain()

	r := gin.Default()
	tpl = template.Must(template.New("").ParseGlob("data/templates/new/*.gohtml"))

	//private, _ := os.LookupEnv("PRIVATE")
	//public, _ := os.LookupEnv("PUBLIC")
	//mg := mailgun.NewMailgun("mail.therileyjohnson.com", private, public)

	/* FILE HANDLERS */
	r.Use(static.Serve("/static", static.LocalFile("static/", true)))
	r.GET("/favicon.ico", func(g *gin.Context) { http.ServeFile(g.Writer, g.Request, "/static/img/favicon.ico") })

	/* ROUTE HANDLERS */

	r.NoRoute(func(c *gin.Context) {
		tpl.ExecuteTemplate(c.Writer, "error.gohtml", "404 Page not found :(")
	})

	r.GET("/", func(g *gin.Context) {
		td := defaultTemplateData()
		td.Authenticated = isActiveSession(g.Request)
		go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "index.gohtml", *td))

		// players := users{}
		// err := queryPlayersByScore(&players)
		// go errorLogger(g.Request.URL.String(), "1", err)
		// if isActiveSession(g.Request) {
		// 	err = tpl.ExecuteTemplate(g.Writer, "indexIn.gohtml", players)
		// 	go errorLogger(g.Request.URL.String(), "2", err)
		// } else {
		// 	err = tpl.ExecuteTemplate(g.Writer, "indexOut.gohtml", players)
		// 	go errorLogger(g.Request.URL.String(), "3", err)
		// }
	})

	r.Run(":4800")
}

func addChallenge(c *gin.Context) error {
	pid := getIDFromSession(c.Request)
	oid, err := strconv.ParseUint(c.PostForm("pid"), 10, 32)

	if oid == 0 {
		return errors.New("Need to select a user")
	}

	if err != nil {
		return errors.New("Couldn't parse Opponent ID")
	}

	if pid == oid {
		return errors.New("Challenger ID cannot be the same as the Acceptor ID")
	}

	wid, err := strconv.ParseUint(c.PostForm("wpid"), 10, 32)

	if err != nil {
		return errors.New("Couldn't parse Winner ID")
	}

	if wid != oid && wid != pid {
		return errors.New("The Winner ID needs to either be the Challenger ID or Opponent ID")
	}

	date := c.PostForm("date")

	_, err = queryPlayer(oid)

	if err == sql.ErrNoRows {
		return errors.New("An Opponent with that ID does not exist")
	}

	_, err = db.Exec("INSERT INTO PLAYER_CHALLENGES VALUES ($1, $2, $3, $4, $5)", getUUID(), date, oid, pid, wid)

	if err != nil {
		return errors.New("Error with adding the challenge, please try again")
	}

	return nil
}

func addPlayer(e, f, l, p string) error {
	funcLocation := "addPlayer"
	_, err := db.Exec(`INSERT INTO PLAYERS VALUES ($1, $2, $3, $4, 300)`, e, f, l, p)

	if err != nil {
		go errorBasicLogger(funcLocation, "1", err)
		return err
	}

	return nil
}

func checkAuth(c *gin.Context, f func(*gin.Context)) {
	if isActiveSession(c.Request) {
		f(c)
	} else {
		c.Redirect(303, "/")
	}
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func dbConfig() map[string]string {
	conf := make(map[string]string)
	conflist := []string{dbhost, dbport, dbuser, dbpass, dbname}
	for _, config := range conflist {
		con, ok := os.LookupEnv(config)
		if !ok {
			panic(fmt.Sprintf("%s environment variable required but not set", config))
		}
		conf[config] = con
	}
	return conf
}

func defaultTemplateData() *templateData {
	td := &templateData{}
	td.Theme, td.ThemeAlt, td.ThemeHighlighter, td.ThemeHighlighterAlt = "0,84,164", "252,225,2", "255,255,255", "48,48,48"
	return td
}

func errorBasicLogger(location, sublocation string, err error) {
	errorChannel <- locationalError{err, location, sublocation}
}

func errorDrain() {
	var lErr locationalError
	for {
		select {
		case lErr = <-errorChannel:
			fmt.Println(lErr.Location, lErr.Sublocation, lErr.Error.Error())
			//Handle Error Logging Here
		}
	}
}

func errorLogger(location, sublocation string, err error) {
	if err != nil {
		errorBasicLogger(location, sublocation, err)
	}
}

func getIDFromSession(r *http.Request) uint64 {
	var id uint64
	val, _ := r.Cookie("uuid")
	db.QueryRow(`
		SELECT 
		pid 
		FROM PLAYER_SESSIONS 
		WHERE uuid=$1`, val.Value,
	).Scan(&id)
	return id
}

func getUUID() string {
	var err error
	var uid uuid.UUID
	for uid, err = uuid.NewV4(); err != nil; {
		uid, err = uuid.NewV4()
	}
	return uid.String()
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func isActiveSession(r *http.Request) bool {
	funcLocation := "isActiveSession"
	val, err := r.Cookie("uuid")
	if err == nil {
		var id int

		err = db.QueryRow(`
		SELECT 
		pid 
		FROM PLAYER_SESSIONS 
		WHERE uuid=$1`, val.Value,
		).Scan(&id)

		if err != sql.ErrNoRows {
			if err == nil {
				return true
			}
			go errorBasicLogger(funcLocation, "1", err)
		}
	}
	return false
}

func queryPlayer(id uint64) (user, error) {
	u := user{}

	err := db.QueryRow(`
		SELECT 
		email, fname, lname, pid, score 
		FROM PLAYERS WHERE pid=$1`, id,
	).Scan(
		&u.Email, &u.Fname, &u.Lname, &u.ID, &u.Score,
	)

	if err == sql.ErrNoRows {
		return user{}, sql.ErrNoRows
	}

	if err != nil {
		return user{}, err
	}

	return u, nil
}

func queryPlayersByFname(U *users, Cuser uint64) error {
	funcLocation := "queryPlayersByScore"
	//Order by descending because the
	//ordering is reversed when
	//appended to the U.Users list
	rows, err := db.Query(`
		SELECT
		email, fname, lname, pid, score
		FROM PLAYERS
		WHERE NOT pid=$1
		ORDER BY fname`, Cuser,
	)

	if err != nil {
		go errorBasicLogger(funcLocation, "1", err)
		return err
	}

	defer rows.Close()

	for rows.Next() {
		u := user{}
		err = rows.Scan(
			&u.Email,
			&u.Fname,
			&u.Lname,
			&u.ID,
			&u.Score,
		)
		if err != nil {
			go errorBasicLogger(funcLocation, "2", err)
			return err
		}
		U.Users = append(U.Users, u)
	}

	err = rows.Err()

	if err != nil {
		go errorBasicLogger(funcLocation, "3", err)
		return err
	}

	return nil
}

func queryPlayersByScore(U *users) error {
	funcLocation := "queryPlayersByScore"
	//Order by descending because the
	//ordering is reversed when
	//appended to the U.Users list
	rows, err := db.Query(`
		SELECT
		email, fname, lname, pid, score
		FROM PLAYERS
		ORDER BY score DESC`,
	)

	if err != nil {
		go errorBasicLogger(funcLocation, "1", err)
		return err
	}

	defer rows.Close()

	for rows.Next() {
		u := user{}
		err = rows.Scan(
			&u.Email,
			&u.Fname,
			&u.Lname,
			&u.ID,
			&u.Score,
		)
		if err != nil {
			go errorBasicLogger(funcLocation, "2", err)
			return err
		}
		U.Users = append(U.Users, u)
	}

	err = rows.Err()

	if err != nil {
		go errorBasicLogger(funcLocation, "3", err)
		return err
	}

	return nil
}
