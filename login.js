const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const User = require("./login_panel/models/User");

const app = express();

mongoose.connect("mongodb://127.0.0.1:27017/loginDB")
.then(() => console.log("✅ MongoDB connected"))
.catch((err) => console.log("❌ Database Error:", err));

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("login_panel"));
app.set("view engine", "ejs");
app.set("views", "login_panel/views");

app.use(
  session({
    secret: "sample-secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});//disabling cache and prevent from back button triggering

function checkAuth(req, res, next) {
  if (req.session.user) next();
  else res.redirect("/login");
}

app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => res.render("login", { message: "" }));
app.get("/signup", (req, res) => res.render("signup", { message: "" }));

app.post("/signup", async (req, res) => {
    const { name, email, phone, address, password } = req.body;

    if (!name || !email || !phone || !password || !address)
        return res.render('signup', { message: 'All fields are required!' });

    if (!/^\d{10}$/.test(phone))
        return res.render('signup', { message: 'Phone number must be 10 digits!' });

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.render('signup', { message: 'Invalid email format!' });

    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,12}$/.test(password))
        return res.render('signup', { message: 'Password must be 8–12 characters and include uppercase, lowercase, number, and symbol!' });

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.render("signup", { message: "User already exists with this email!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, phone, address, password: hashedPassword });
    await newUser.save();

    console.log("🆕 User Registered:", name);
    res.redirect("/login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.render("login", { message: "No user found with this email!" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.render("login", { message: "Incorrect password!" });

  req.session.user = user;
  res.redirect("/dashboard");
});

app.get("/dashboard", checkAuth, (req, res) => {
  res.render("dashboard", { user: req.session.user });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.log(err);
    res.redirect("/login");
  });
});

app.listen(3000)