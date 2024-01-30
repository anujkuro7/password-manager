import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt"
import session from "express-session";


env.config();
const app = express();
const port = 3000;
const saltRounds = 10;
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});

await db.connect();

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});
app.get("/password", async (req, res) => {
    const userEmail = req.session.userEmail;
    const pass = await db.query("SELECT id, password FROM users where email=$1", [userEmail]);
    const id = pass.rows[0].id;
    session.id = id;
    const userDetails = await db.query("SELECT * FROM passwords JOIN users ON users.id=passwords.userid WHERE id=$1", [id]);
    res.render("password.ejs", {
        userData: userDetails.rows
    });
})
app.post("/register", async (req, res) => {
    const userEmail = req.body.username;
    const userPassword = req.body.password;
    req.session.userEmail = req.body.username;
    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
            userEmail,
        ]);
        if (checkResult.rows.length > 0) {
            res.send("Email already exists. Try logging in.");
        } else {
            //hashing the password and saving it in the database
            bcrypt.hash(userPassword, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
                        [userEmail, hash]
                    );
                    res.redirect("/password");
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});
app.post("/login", async (req, res) => {
    const userEmail = req.body.username;
    const loginPassword = req.body.password;
    req.session.userEmail = req.body.username;
    const result = await db.query("SELECT * FROM users where email=$1", [userEmail]);
    if (result.rows.length > 0) {
        const pass = await db.query("SELECT id, password FROM users where email=$1", [userEmail]);
        const storedHashedPassword = pass.rows[0].password;
        bcrypt.compare(loginPassword, storedHashedPassword, async (err, result) => {
            if (result) {
                res.redirect("/password")
            }
            else {
                res.send("incorrect password");
            }
        })
    }
    else {
        res.send("invalid user");
    }
});
app.post("/submit", async (req, res) => {
    const enteredUsername = req.body.username;
    const enteredPassword = req.body.password;
    const website = req.body.website;
    const userid = await db.query("SELECT id FROM users where email=$1", [req.session.userEmail]);
    const requiredUserid = userid.rows[0].id;
    try {
        const result = await db.query("INSERT INTO passwords(userid,website,username,passwords) VALUES ($1,$2,$3,$4)", [requiredUserid, website, enteredUsername, enteredPassword]);
        if (result) {
            res.redirect("/password")
        } else {
            res.send("error inserting data");
        }
    } catch (err) {
        console.log(err);
    }
});

app.get("/delete", async (req, res) => {
    const serialIdToDelete = req.query.serialid;
    try {
        const deleteDetail = await db.query("DELETE FROM passwords WHERE serialid=$1", [serialIdToDelete]);
        if (deleteDetail) {
            res.redirect("/password");
        } else {
            res.send("error deleting");
        }
    } catch (err) {
        res.send(err);
    }
});
app.listen(port, () => {
    console.log(`listening on port ${port}`);
})