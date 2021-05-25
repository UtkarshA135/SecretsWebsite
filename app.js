
//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const app = express();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var FacebookStrategy  = require("passport-facebook").Strategy;
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use(session({
  secret:process.env.SECRET,
  resave:false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secretsDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema(
  {
    email:String,
    password:String,
    googleId :String,
    facebookId:String,
    secret: String
  });

  userSchema.plugin(passportLocalMongoose);
  userSchema.plugin(findOrCreate);

const User = mongoose.model("user",userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:  "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {

      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",


  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
})

app.get("/login", function(req, res) {
res.render("login");

});


app.get("/register", function(req, res) {
res.render("register");

});

app.get("/secrets",function(req,res){
  User.find({secret:{$ne:null}},function(err,results){
    if(err)
    console.log(err);
    else
    {
      res.render("secrets",{secretsList:results})
    }
  })
})
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
  app.get('/auth/facebook',
  passport.authenticate('facebook', ));
  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });

app.post("/login",function(req,res){

const user = User({
  username:req.body.username,
  password:req.body.password
});
req.login(user,function(err){
  if(err)
  {console.log(err)
    res.redirect("/login");
}
else{
  passport.authenticate("local")(req,res,function(){
    res.redirect("/secrets");
  })
}
});});

app.get('/logout', (req, res) => {
  req.session = null;
  req.logout();
  res.redirect('/');
})


app.post("/submit",function(req,res){
  const submitedSecret = req.body.secret;

  User.findById(req.user._id,function(err,foundUser){
    if(err)
    console.log(err);
    else{
      if(foundUser)
      {foundUser.secret = submitedSecret;
      foundUser.save(function(){
        res.redirect("/secrets")
      })
    }}
  })
})
app.get("/submit",function(req,res){
  if(req.isAuthenticated())
  res.render("submit");
  else
  res.redirect("/login");
})
app.post("/register",function(req,res){
User.register({username:req.body.username},req.body.password,function(err){
  if(err)
  {
    console.log(err);
    res.redirect("/register");
  }
  else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    })
  }
})
})

app.listen(process.env.PORT||3000, function() {
  console.log("Server started on port 3000");
});
