require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const helmet = require("helmet");
const csrf = require("csurf");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.set("view engine", "ejs");

//Lab5------------------------------
// Database connection
// mongoose
//   .connect(process.env.DB_CONNECTION, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => console.log("Connected to MongoDB"))
//   .catch((err) => console.error("Database connection error:", err));

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.DB_CONNECTION,
      collectionName: "sessions",
    }),
    cookie: {
      httpOnly: true, // Prevents JavaScript access
      secure: false, // Set to true in production (requires HTTPS)
      maxAge: 1000 * 60 * 15, // 15 minutes
    },
  })
);

// CSRF Protection
const csrfProtection = csrf();
app.use(csrfProtection);

// Middleware to send CSRF token to client
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
//Lab5------------------------------

//lab4--------------------------------------
// Connect to MongoDB
mongoose
  .connect("mongodb://127.0.0.1:27017/google-sso", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));
//lab4--------------------------------------

// Middleware/////////////////////
app.use(bodyParser.json());
// Helmet for securing HTTP headers
app.use(helmet());
app.use(express.static("public")); // Serves static files from "public" folder

// Session configuration
// app.use(
//   session({
//     secret: process.env.SESSION_SECRET,
//     resave: false,
//     saveUninitialized: false,
//     cookie: { secure: false }, // Set to true in production
//   })
// );

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// User database (in-memory for this example)
const users = {};

//lab4--------------------------------------
const User = require("./models/User");

// Passport Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log("Google profile received:", profile);

        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          console.log("Creating a new user...");
          user = new User({
            googleId: profile.id,
            username: profile.displayName,
            loginCount: 1,
          });
        } else {
          console.log("User found, updating login count...");
          user.loginCount += 1;

          // Promote to 'superuser' if login count exceeds threshold
          if (user.loginCount > 3) {
            user.role = "superuser";
          }
        }
        await user.save();
        console.log("User saved successfully:", user);
        return done(null, user);
      } catch (err) {
        console.error("Error in Google Strategy:", err);
        return done(err, null);
      }
    }
  )
);
//lab4--------------------------------------

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      return done(new Error("User not found"), null);
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/error" }),
  (req, res) => {
    if (req.user.role === "superuser") {
      res.redirect("/super-dashboard"); // Redirect superusers here
    } else {
      res.redirect("/dashboard"); // Redirect normal users here
    }
  }
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/signin", (req, res) => {
  res.render("signin");
});

app.get("/error", (req, res) => {
  res.render("error");
});

// app.get("/dashboard", (req, res) => {
//   res.render("dashboard", { username: req.user.username });
// });

//lab4--------------------------------------
const { ensureAuthenticated, ensureSuperUser } = require("./middlewares/auth");

// Superuser-only route
app.get("/super-dashboard", ensureSuperUser, (req, res) => {
  res.render("super-dashboard", {
    username: req.user.username,
    role: req.user.role,
  });
});

// Normal dashboard route (accessible to all authenticated users)
app.get("/dashboard", ensureAuthenticated, (req, res) => {
  res.render("dashboard", {
    username: req.user.username,
    role: req.user.role,
  });
});

//   res.send(
//     `Welcome ${req.user.username}! Role: ${req.user.role} <a href="/logout">Logout</a>`
//   );
// });

//lab4--------------------------------------

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
