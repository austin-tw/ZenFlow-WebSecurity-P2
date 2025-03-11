require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;

//?--------
const authorize = require("./middlewares/authorize");
const authMiddleware = require("./middlewares/auth");
app.use(express.json());
app.set("view engine", "ejs");

// Middleware/////////////////////
app.use(bodyParser.json());
// Helmet for securing HTTP headers
app.use(helmet());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Set to true in production
  })
);

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// User database (in-memory for this example)
const users = {};

// Passport configuration for Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        username: profile.displayName,
        role: "user", // Default role
      };
      users[profile.id] = user; // Store user in memory
      return done(null, user);
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users[id]));

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/userAuth", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected!"))
  .catch((err) => console.log(err));

////////Routes/////////
app.get("/", (req, res) => {
  res.render("index");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Welcome ${req.user.username}! <a href="/logout">Logout</a>`);
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Login checker/////////////////////

////////////////////////////

app.get("/protected", authMiddleware, authorize("admin"), (req, res) => {
  res.status(200).json({ message: "Welcome admin users" });
});

const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

const adminRoutes = require("./routes/admin");
app.use("/api/admin", adminRoutes);

// Start the server
//const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server 
running on port ${PORT}`)
);
