package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

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
	go errorDrain()

	r := gin.Default()
	tpl = template.Must(template.New("").ParseGlob("data/templates/*.gohtml"))

	private, _ := os.LookupEnv("PRIVATE")
	public, _ := os.LookupEnv("PUBLIC")
	mg := mailgun.NewMailgun("mail.therileyjohnson.com", private, public)

	/* FILE HANDLERS */
	r.Use(static.Serve("/static", static.LocalFile("static/", true)))
	r.GET("/favicon.ico", func(g *gin.Context) { http.ServeFile(g.Writer, g.Request, "/static/img/favicon.ico") })

	/* ROUTE HANDLERS */
	r.NoRoute(func(c *gin.Context) {
		tpl.ExecuteTemplate(c.Writer, "error.gohtml", "404 Page not found :(")
	})

	r.GET("/", func(g *gin.Context) {
		players := users{}
		err := queryPlayersByScore(&players)
		go errorLogger(g.Request.URL.String(), "1", err)
		if isActiveSession(g.Request) {
			err = tpl.ExecuteTemplate(g.Writer, "indexIn.gohtml", players)
			go errorLogger(g.Request.URL.String(), "2", err)
		} else {
			err = tpl.ExecuteTemplate(g.Writer, "indexOut.gohtml", players)
			go errorLogger(g.Request.URL.String(), "3", err)
		}
	})

	r.POST("/accept/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			var ascore, iscore int
			id := g.Param("id")
			uid := getIDFromSession(g.Request)
			c := challenge{}

			err := db.QueryRow(
				`SELECT * FROM PLAYER_CHALLENGES WHERE acceptor=$1 AND id=$2`, uid, id,
			).Scan(
				&c.ID, &c.Date, &c.Acceptor, &c.Initiator, &c.Winner,
			)

			if err == sql.ErrNoRows {
				go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "Couldn't find that challenge, sorry"))
			} else {
				go errorLogger(g.Request.URL.String(), "2", err)
				err = db.QueryRow(
					`SELECT score FROM PLAYERS WHERE pid=$1`, c.Acceptor,
				).Scan(&ascore)
				go errorLogger(g.Request.URL.String(), "3", err)
				err = db.QueryRow(
					`SELECT score FROM PLAYERS WHERE pid=$1`, c.Initiator,
				).Scan(&iscore)
				go errorLogger(g.Request.URL.String(), "4", err)
				//Score calculation:
				//Calculate the expected scores, then based off of the winner and loser get the amount of points each player earned
				//ExpectedPlayer1 = 1 / (1 + (10^(Player2 - Player1) / 400))
				//if Player1 won:
				//ScorePlayer1 = Player1OriginalScore + (1 - ExpectedPlayer1) * k
				//if Player1 lost:
				//ScorePlayer1 = Player1OriginalScore + (0 - ExpectedPlayer1) * k
				expectedA, expectedI := 1/(1+math.Pow(10, float64(iscore-ascore)/400)), 1/(1+math.Pow(10, float64(ascore-iscore)/400))
				outcomeA, outcomeI := 1.0, 0.0

				if c.Winner == c.Initiator {
					outcomeA, outcomeI = 0.0, 1.0
				}

				nAscore := ascore + int((outcomeA-expectedA)*k)
				_, err = db.Exec("UPDATE PLAYERS SET score=$1 WHERE pid=$2", nAscore, c.Acceptor)
				go errorLogger(g.Request.URL.String(), "5", err)
				nIscore := iscore + int((outcomeI-expectedI)*k)
				_, err = db.Exec("UPDATE PLAYERS SET score=$1 WHERE pid=$2", nIscore, c.Initiator)
				go errorLogger(g.Request.URL.String(), "6", err)
				_, err = db.Exec("DELETE FROM PLAYER_CHALLENGES WHERE acceptor=$1 AND id=$2", uid, id)
				go errorLogger(g.Request.URL.String(), "7", err)
				g.Redirect(303, "/confirm")
			}
		})
	})

	r.POST("/cancel/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := g.Param("id")
			uid := getIDFromSession(g.Request)

			_, err := db.Exec("DELETE FROM PLAYER_CHALLENGES WHERE initiator=$1 AND id=$2", uid, id)
			go errorLogger(c.Request.URL.String(), "1", err)
			g.Redirect(303, "/confirm")
		})
	})

	r.GET("/confirm", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			type info struct{ Fname, Lname string }

			var err error
			var oid uint64
			var u user

			cd := confirmData{}
			c := challenge{}
			pid := getIDFromSession(g.Request)
			pmap := make(map[string]info)

			cd.Initiator, err = queryPlayer(pid)

			if err == nil {
				err = queryPlayersByFname(&cd.users, pid)
				if err == nil {
					rows, err := db.Query(`SELECT * FROM PLAYER_CHALLENGES WHERE acceptor=$1`, pid)
					go errorLogger(g.Request.URL.String(), "1", err)
					if err == nil {
						fmt.Println(cd.Users)
						for rows.Next() && cd.Error == "" {
							c = challenge{}
							err = rows.Scan(
								&c.ID,
								&c.Date,
								&c.Acceptor,
								&c.Initiator,
								&c.Winner,
							)

							if err != nil {
								cd.Error = "Error in getting acceptor data"
								go errorLogger(g.Request.URL.String(), "2", err)
							} else {
								if _, exists := pmap[c.Initiator]; !exists {
									oid, err = strconv.ParseUint(c.Initiator, 10, 32)
									go errorLogger(g.Request.URL.String(), "3", err)
									u, err = queryPlayer(oid)
									go errorLogger(g.Request.URL.String(), "4", err)
									pmap[c.Initiator] = info{u.Fname, u.Lname}
								}

								c.Opponent.Fname, c.Opponent.Lname = pmap[c.Initiator].Fname, pmap[c.Initiator].Lname

								if c.Initiator == c.Winner {
									c.WinningString = "won on"
								} else {
									c.WinningString = "lost on"
								}

								cd.Achallenges = append(cd.Achallenges, c)
							}
						}
						rows.Close()

						if err == nil {
							rows, err = db.Query(`SELECT * FROM PLAYER_CHALLENGES WHERE initiator=$1`, pid)
							if err == nil {
								for rows.Next() && cd.Error == "" {
									c = challenge{}
									err = rows.Scan(
										&c.ID,
										&c.Date,
										&c.Acceptor,
										&c.Initiator,
										&c.Winner,
									)

									if err != nil {
										cd.Error = "Error in getting acceptor data"
										go errorLogger(g.Request.URL.String(), "5", err)
									} else {
										if _, exists := pmap[c.Acceptor]; !exists {
											oid, err = strconv.ParseUint(c.Acceptor, 10, 32)
											go errorLogger(g.Request.URL.String(), "6", err)
											u, err = queryPlayer(oid)
											go errorLogger(g.Request.URL.String(), "7", err)
											pmap[c.Acceptor] = info{u.Fname, u.Lname}
										}

										c.Opponent.Fname, c.Opponent.Lname = pmap[c.Acceptor].Fname, pmap[c.Acceptor].Lname

										if c.Acceptor == c.Winner {
											c.WinningString = "won on"
										} else {
											c.WinningString = "lost on"
										}

										cd.Ichallenges = append(cd.Ichallenges, c)
									}
								}
							} else {
								go errorLogger(g.Request.URL.String(), "8", err)
							}
							rows.Close()
						} else {
							go errorLogger(g.Request.URL.String(), "9", err)
						}
					} else {
						rows.Close()
						cd.Error = "Could not get acceptor data"
						go errorLogger(g.Request.URL.String(), "10", err)
					}
				} else {
					cd.Error = "Could not get player ID data"
					errorLogger(g.Request.URL.String(), "11", err)
				}
			} else {
				cd.Error = "Could not get initiator data"
				errorLogger(g.Request.URL.String(), "12", err)
			}

			go errorLogger(g.Request.URL.String(), "13", tpl.ExecuteTemplate(g.Writer, "gameConfirm.gohtml", cd))
		})
	})

	r.POST("/confirm", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			err := addChallenge(g)
			if err != nil {
				go errorLogger(g.Request.URL.String(), "1", err)
				go errorLogger(g.Request.URL.String(), "2", tpl.ExecuteTemplate(g.Writer, "error.gohtml", err.Error()))
			} else {
				g.Redirect(303, "/confirm")
			}
		})
	})

	r.POST("/deny/:id", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := g.Param("id")
			uid := getIDFromSession(g.Request)
			_, err := db.Exec("DELETE FROM PLAYER_CHALLENGES WHERE acceptor=$1 AND id=$2", uid, id)

			go errorLogger(g.Request.URL.String(), "1", err)
			g.Redirect(303, "/confirm")
		})
	})

	r.GET("/login", func(g *gin.Context) {
		if isActiveSession(g.Request) {
			go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "You're already logged in!"))
		} else {
			go errorLogger(g.Request.URL.String(), "2", tpl.ExecuteTemplate(g.Writer, "login.gohtml", nil))
		}
	})

	r.POST("/login", func(g *gin.Context) {
		email := strings.ToLower(g.PostForm("email"))
		password := g.PostForm("password")
		ua := userAuth{}

		err := db.QueryRow("SELECT * FROM PLAYERS WHERE email=$1", email).Scan(&ua.Email, &ua.Fname, &ua.Lname, &ua.Password, &ua.Score, &ua.ID)

		if err == sql.ErrNoRows {
			go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "login.gohtml", "BAD LOGIN!"))
		} else {
			if err != nil {
				go errorLogger(g.Request.URL.String(), "2", err)
				go errorLogger(g.Request.URL.String(), "3", tpl.ExecuteTemplate(g.Writer, "login.gohtml", "ERROR LOGGING IN!"))
			} else {
				if checkPasswordHash(password, ua.Password) {
					uid := getUUID()
					http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", Value: uid})

					_, err = db.Exec("INSERT INTO PLAYER_SESSIONS (pid, uuid) VALUES ($1, $2)", ua.ID, uid)
					go errorLogger(g.Request.URL.String(), "4", err)

					g.Redirect(303, "/")
				} else {
					go errorLogger(g.Request.URL.String(), "7", tpl.ExecuteTemplate(g.Writer, "login.gohtml", "BAD LOGIN!"))
				}
			}
		}
	})

	r.GET("/logout", func(g *gin.Context) {
		if isActiveSession(g.Request) {
			val, err := g.Request.Cookie("uuid")
			go errorLogger(g.Request.URL.String(), "1", err)

			http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", MaxAge: -1})
			_, err = db.Query("DELETE FROM PLAYER_SESSIONS WHERE uuid=$1", val.Value)
			go errorLogger(g.Request.URL.String(), "2", err)

			g.Redirect(307, "/")
		} else {
			g.Redirect(303, "/login")
		}
	})

	r.GET("/profile", func(c *gin.Context) {
		checkAuth(c, func(g *gin.Context) {
			id := getIDFromSession(g.Request)
			player, err := queryPlayer(id)

			if err != nil {
				go errorBasicLogger(g.Request.URL.String(), "1", err)
				go errorLogger(g.Request.URL.String(), "2", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "Error fetching your profile, sorry"))
			} else {
				go errorLogger(g.Request.URL.String(), "3", tpl.ExecuteTemplate(g.Writer, "myProfile.gohtml", player))
			}
		})
	})

	r.GET("/profile/:id", func(g *gin.Context) {
		id, err := strconv.ParseUint(g.Param("id"), 10, 32)
		if err == nil {
			player, err := queryPlayer(id)
			if err == sql.ErrNoRows {
				go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "That player ID does not exist"))
			} else if err != nil {
				go errorBasicLogger(g.Request.URL.String(), "2", err)
				go errorLogger(g.Request.URL.String(), "3", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "Error finding player with that ID"))
			} else if isActiveSession(g.Request) {
				go errorLogger(g.Request.URL.String(), "4", tpl.ExecuteTemplate(g.Writer, "profileIn.gohtml", player))
			} else {
				go errorLogger(g.Request.URL.String(), "5", tpl.ExecuteTemplate(g.Writer, "profileOut.gohtml", player))
			}
		} else {
			go errorBasicLogger(g.Request.URL.String(), "6", err)
			go errorLogger(g.Request.URL.String(), "7", tpl.ExecuteTemplate(g.Writer, "error.gohtml", "That's not a valid player ID"))
		}
	})

	r.GET("/register", func(g *gin.Context) {
		go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "register.gohtml", nil))
	})

	r.POST("/register", func(g *gin.Context) {
		matchEmail := false
		emailDomains := []string{"trojans.dsu.edu", "pluto.dsu.edu", "dsu.edu"}
		email := strings.ToLower(g.PostForm("email"))

		for _, emailRegex := range emailDomains {
			r := regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9][A-Za-z0-9_\+\.]*@%s$`, emailRegex))
			if r.Match([]byte(email)) {
				matchEmail = true
			}
		}

		if !matchEmail {
			go errorLogger(g.Request.URL.String(), "2", tpl.ExecuteTemplate(g.Writer, "register.gohtml", "EMAIL FORMAT IS INVALID!"))
		} else {
			fname := g.PostForm("fname")
			lname := g.PostForm("lname")
			password := g.PostForm("password")
			cpassword := g.PostForm("cpassword")
			if cpassword != password {
				go errorLogger(g.Request.URL.String(), "3", tpl.ExecuteTemplate(g.Writer, "register.gohtml", "PASSWORDS DO NOT MATCH!"))
			} else {
				ua := userAuth{}
				err := db.QueryRow("SELECT email FROM PLAYERS WHERE email=$1", email).Scan(&ua.Email)

				if err != sql.ErrNoRows {
					go errorLogger(g.Request.URL.String(), "4", err)
					go errorLogger(g.Request.URL.String(), "5", tpl.ExecuteTemplate(g.Writer, "register.gohtml", "USER ALREADY EXISTS!"))
				} else {
					var hpassword string
					for hpassword, err = hashPassword(password); err != nil; {
						hpassword, err = hashPassword(password)
					}

					uid := getUUID()
					_, err = db.Exec("INSERT INTO PLAYER_CONFIRMATION VALUES ($1, $2, $3, $4, $5)",
						uid, email, fname, lname, hpassword)
					if err != nil {
						go errorBasicLogger(g.Request.URL.String(), "6", err)
						go errorLogger(g.Request.URL.String(), "7", tpl.ExecuteTemplate(g.Writer, "register.gohtml", "Error with adding to registration pool, try again; if the problem persists, you know who to talk to"))
					} else {
						_, _, err = mg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", "Registration", fmt.Sprintf("Click %s:4800/register/%s to confirm your email!", url, uid), email))
						if err != nil {
							go errorBasicLogger(g.Request.URL.String(), "8", err)
							go errorLogger(g.Request.URL.String(), "9", tpl.ExecuteTemplate(g.Writer, "register.gohtml", "Error with sending confirmation email for registration, try again; if the problem persists, you know who to talk to"))
						} else {
							go errorLogger(g.Request.URL.String(), "10", tpl.ExecuteTemplate(g.Writer, "registerFinishOut.gohtml", "Please confirm your email to finish registration"))
						}
					}
				}
			}
		}
	})

	r.GET("/register/:id", func(g *gin.Context) {
		u := user{}
		err := db.QueryRow(
			`SELECT 
			email, fname, lname, password 
			FROM PLAYER_CONFIRMATION 
			WHERE uuid=$1`, g.Param("id"),
		).Scan(
			&u.Email, &u.Fname, &u.Lname, &u.Password,
		)

		if err == sql.ErrNoRows {
			go errorLogger(g.Request.URL.String(), "1", tpl.ExecuteTemplate(g.Writer, "registrationBad.gohtml", nil))
		} else {
			go errorLogger(g.Request.URL.String(), "2", err)
			addPlayer(u.Email, u.Fname, u.Lname, u.Password)
			db.QueryRow(`SELECT pid FROM PLAYERS WHERE email=$1`, u.Email).Scan(&u.ID)
			uid := getUUID()
			http.SetCookie(g.Writer, &http.Cookie{Name: "uuid", Value: uid})
			go errorLogger(g.Request.URL.String(), "3", tpl.ExecuteTemplate(g.Writer, "registerFinishIn.gohtml", "You have finished registration!"))

			_, err = db.Exec(`DELETE FROM PLAYER_CONFIRMATION WHERE email=$1`, u.Email)
			go errorLogger(g.Request.URL.String(), "4", err)
			_, err = db.Exec(`INSERT INTO PLAYER_SESSIONS VALUES ($1, $2)`, u.ID, uid)
			go errorLogger(g.Request.URL.String(), "5", err)
		}
	})

	r.Run(":4800")
}

func addChallenge(c *gin.Context) error {
	pid := getIDFromSession(c.Request)
	oid, err := strconv.ParseUint(c.PostForm("pid"), 10, 32)

	if oid == 0 {
		return fmt.Errorf("Need to select a user")
	}

	if err != nil {
		return fmt.Errorf("Couldn't parse Opponent ID")
	}

	if pid == oid {
		return fmt.Errorf("Challenger ID cannot be the same as the Acceptor ID")
	}

	wid, err := strconv.ParseUint(c.PostForm("wpid"), 10, 32)

	if err != nil {
		return fmt.Errorf("Couldn't parse Winner ID")
	}

	if wid != oid && wid != pid {
		return fmt.Errorf("The Winner ID needs to either be the Challenger ID or Opponent ID")
	}

	date := c.PostForm("date")

	_, err = queryPlayer(oid)

	if err == sql.ErrNoRows {
		return fmt.Errorf("An Opponent with that ID does not exist")
	}

	_, err = db.Exec("INSERT INTO PLAYER_CHALLENGES VALUES ($1, $2, $3, $4, $5)", getUUID(), date, oid, pid, wid)

	if err != nil {
		return fmt.Errorf("Error with adding the challenge, please try again")
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

func errorBasicLogger(location, sublocation string, err error) {
	errorChannel <- locationalError{err, location, sublocation}
}

func errorDrain() {
	var lErr locationalError
	for {
		select {
		case lErr = <-errorChannel:
			fmt.Println(lErr.Location, lErr.Sublocation, lErr)
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
