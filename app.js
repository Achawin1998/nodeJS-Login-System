const express = require("express");
const pg = require("pg");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const env = require("dotenv")

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json()); // ยอมรับข้อมูลที่เป็น json เท่านั้น
app.use(express.static(path.join(__dirname, "public"))) // set static folder
app.use(session({ // เก็บ session สำรหรับ login
    secret: "secret",
    resave: false, // ป้องกันการบันทึก session ที่ไม่ได้มีการเปลี่ยนแปลง
    saveUninitialized: true // เป็นการบันทึก session แม้ว่ายังไม่มีการบันทึกข้อมูล
}))

//  set EJS as template engine
app.set("view engine", "ejs");

// Middleware to check if the user is logged in
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next(); // ถ้า user log จะให้ใช้ next เพื่อที่จะให้ไปหน้า home ได้
    } else {
        res.redirect("/login") // ถ้าไม่ได้ login แล้วพยายามเข้าหน้า home ก็เด้งไปหน้า login
    }
}

const ifLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return res.redirect("/home")
    }
    next()
}

//Connect postgreSQL database.
env.config()

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
});

db.connect((err) => {
    if (err) {
        throw err;
    }

    console.log("Connect to database successfully!")
})

// Routes
app.get("/", (req, res) => {
    res.render("index", { user: req.session.user }) 
})

app.get("/home", isAuthenticated,  (req, res) => {
    console.log(req.session.user);
    res.render("home", { user: req.session.user });
})

app.get("/login", ifLoggedIn, (req, res) => {
    res.render("login")
})

app.get("/register", ifLoggedIn, (req, res) => {
    res.render("register")
})

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
})

app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const checkEmailQuery = await db.query("SELECT * FROM users WHERE email = $1",[email])
        if (checkEmailQuery.rows.length > 0) {
            res.render("register", { error_msg: "Email already registerd. Please use a different email."})
        } else {
            const hashPassword = await bcrypt.hash(password, 10)
            const insertUserQuery = await db.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",[name, email, hashPassword])
            res.render("register", { success_msg: "Registration successfully!"})
        }
    } catch (error) {
        console.log(error)
    }
})

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1",[email])

    if (checkEmail.rows.length > 0) {
        const user = checkEmail.rows[0]
        const passCheck = await bcrypt.compare(password, user.password);
        
        if (passCheck) {
            req.session.user = user;
            res.redirect("/home")
        } else {
            res.render("login", { error_msg: "Incorrect password!" });
        }
    } else {
        res.render("login", { error_msg: "User not found" });
    }
})

app.listen(port, () => {
    console.log("Server is running on port 3000.")
})