require("ejs");
require('dotenv').config()

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// security 2
// const encrypt = require("mongoose-encryption");
// security 3: hash
// const md5 = require('js-md5');
// security 4: salting
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// const myPlaintextPassword = 's0/\/\P4$$w0rD';

// security 5
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


// security 6
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

// const secret = process.env.SECRET;

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));

// security 5
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false,
    // cookie: { secure: true }  // or won't be authenticated!
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
// mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// security 2
// userSchema.plugin(encrypt, { requireAuthenticationCode: false, secret: secret, encryptedFields: ["password"]});

// security 5
userSchema.plugin(passportLocalMongoose);
// security 5
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
// work for all strategies even if not local
// passport.serializeUser(function(user, done) {
//     done(null, user.id);
// });
  
// passport.deserializeUser(function(id, done) {
//     User.findById(id).then(function (err, user) {
//         done(err, user);
//     });
// });
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
   
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


// security 6
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",  // udemy: /secrets
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"  // from github MarshallOfSound
},
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile.id, profile.name);
    User.findOrCreate({ username: profile.displayName, googleId: profile.id }, function ( user, err) {
        // if (err){
        //     // console.log("findorcreate fail");console.log(err);
        //     // return self.error(self._createOAuthError('Failed to obtain access token', err)); 
        // }  // by me
        return cb( user, err);
    });
  }
)); // ?? err, user?

app.get("/",(req, res)=>{
    res.render("home");
})

// security 6: (req, res) is necessary
app.get("/auth/google",
    // console.log("going to google");
    // passport.authenticate("google",{ scope: ["profile"] })(req, res)
    passport.authenticate("google",{ scope: ["profile"] })
);

// so that after logging in to google it jumps back to /secrets
app.get('/auth/google/secrets', 
  passport.authenticate('google', { 
    successRedirect: '/secrets',
    failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",(req, res)=>{
    if(req.isAuthenticated()){
        res.redirect("/secrets");
    } else {
        res.render("login");
    }
})

app.get("/register",(req, res)=>{
    res.render("register");
})

app.get("/secrets", (req, res)=>{
    // if (req.isAuthenticated()){res.render("secrets");}
    // else {console.log(req.isAuthenticated());res.redirect("/login");}
    // User.find({"secret": {$ne: null}}, function(err, foundUsers){
    //     if (err){
    //       console.log(err);
    //     } else {
    //       if (foundUsers) {
    //         res.render("secrets", {usersWithSecrets: foundUsers});
    //       }
    //     }
    //   });
    User.find({"secret": {$ne: null}}).then((foundUsers, err)=>{
        if (err){console.log(err);}
        else
         {if (foundUsers){
            res.render("secrets",{usersWithSecrets: foundUsers});
        }}
    })
})

// final
app.get("/submit", (req, res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        // console.log(req.isAuthenticated());
        res.redirect("/login");
    }
})

app.get("/logout", (req, res)=>{
    req.logout((err)=>{
        if (err){console.log(err);}
        else {
            res.redirect("/");
            console.log("User Logged out and this session ended: " + req.headers.cookie);
        }
    });
})

app.post("/submit", (req, res)=>{
    const submittedSecret = req.body.secret;
    // console.log(req.user.id);
    User.findById(req.user.id).then((foundUser,err)=>{
        if (err){console.log(err);}
        else {if (foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save().then(()=>{res.redirect("/secrets");})
        }}
    })
    // not adding to but replacing the last secret
})

app.post("/register", (req, res)=>{
    /* 
    // security 4: salt
    bcrypt.hash(myPlaintextPassword, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            // password: req.body.password
            // security 3: hash
            // password: md5(req.body.password)
            // security 4: salt
            password: hash
        });
        newUser.save().then((savedUser, err)=>{
            if (err){
                console.log(err);
                res.redirect("/register");
            } else {
                res.render("secrets");}
        });
    });
    */
    // User.register({username: req.body.username, active: false}, req.body.password).then((user, err)=>{
    User.register({username: req.body.username}, req.body.password).then((user, err)=>{
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res,()=>{
                console.log("going to secrets");
                res.redirect("/secrets");
            });
        }
    })
})

app.post("/login", (req, res)=>{
    /* const username = req.body.username;
    // security 3: hash
    const password = md5(req.body.password);
    // security 4: salt
    const password = req.body.password;
    User.findOne({email: username}).then((foundUser, err)=>{
        if (err){console.log(err);}
        else {
            if (foundUser){
                // if (foundUser.password === password){
                bcrypt.compare(password, foundUser.password, function(result, err){
                    console.log("Successful login");
                    res.render("secrets");
                })
            }
            else {console.log("no user found");}
        }
    }) */
    /* const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, (err)=>{
        if (err){console.log(err);}
        else {
            passport.authenticate("local")(req, res, ()=>{
                console.log("going to secrets");
                res.redirect("/secrets");
            });
        }
    });*/
    const user = new User({
        username: req.body.username,
        password: req.body.password
      });
    
      req.login(user, function(err){
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function(){
            console.log("redirecting to secrets");
            res.redirect("/secrets");
          });
        }
      });
    
})

app.listen(3000,()=>{
    console.log("Server started on port 3000.");
})