const express = require('express');
const routes = express.Router();
const bodyparser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const user = require('../models.js');
const passport = require('passport');
const session = require('express-session');
const cookieparser = require('cookie-parser')
const flash = require('connect-flash');

routes.use(bodyparser.urlencoded({extended:true}));
routes.use(cookieparser('secret'));
routes.use(session({
    secret:'secret',
    resave:true,
    maxAge:360000,
    saveUninitialized:true,
}))
routes.use(passport.initialize());
routes.use(passport.session());
routes.use(flash());
routes.use((req,res,next) => {
    res.locals.success_message = req.flash('success_message') 
    res.locals.error_message = req.flash('error_message')
    res.locals.error = req.flash('error'); 
    next();
})
const checkAuthenticated = (req,res,next)=>{
    if (req.isAuthenticated()) {
        res.set('Cache-Control','no-cache,rivate,no-store, must-revalidate, post-check=0, pre-check = 0')
        return next();
    }else{
        res.redirect('/login')
    }
}

// mongoose.connect(/*Your dataBase connection*/, {
//     useNewUrlParser: true, useUnifiedTopology: true
// }).then(() => console.log("Database Connected")
// );



routes.get('/', (req,res)=>{
    res.render('index');
});

routes.post('/register', (req, res) => {
    var { email, username, password, confirmpassword } = req.body;
    var err;
    if (!email || !username || !password || !confirmpassword) {
        err = "Please Fill All The Fields...";
        res.render('index', { 'err': err });
    }
    if (password != confirmpassword) {
        error = "Passwords Don't Match";
        res.render('index', { 'err': err, 'email': email, 'username': username });
    }
    if (typeof err == 'undefined') {
        user.findOne({ email: email }, function (err, data) {
            if (err) throw err;
            if (data) {
                console.log("User Exists");
                err = "User Already Exists With This Email...";
                res.render('index', { 'err': error, 'email': email, 'username': username });
            } else {
                bcrypt.genSalt(10, (err, salt) => {
                    if (err) throw err;
                    bcrypt.hash(password, salt, (err, hash) => {
                        if (err) throw err;
                        password = hash;
                        user({
                            email,
                            username,
                            password,
                        }).save((err, data) => {
                            if (err) throw err;
                            req.flash('success_message','registered successfully')
                            res.redirect('/login');
                        });
                    });
                });
            }
        });
    }
});


var localStrategy = require('passport-local').Strategy;
passport.use(new localStrategy({ usernameField: 'email' }, (email, password, done) => {
    user.findOne({ email: email }, (error, data) => {
        if (error) throw error;
        if (!data) {
            return done(null, false, { message: "User Doesn't Exists.." });
        }
        bcrypt.compare(password, data.password, (error, match) => {
            if (error) {
                return done(null, false);
            }
            if (!match) {
                return done(null, false, { message: "Password Doesn't Match" });
            }
            if (match) {
                return done(null, data);
            }
        });
    });
}));

passport.serializeUser(function (user, cb) {
    cb(null, user.id);
});

passport.deserializeUser(function (id, cb) {
    user.findById(id, function (error, user) {
        cb(error, user);
    });
});

routes.get('/login', (req,res)=>{
    res.render('login');
})
routes.post('/login',(req,res,next)=>{
    passport.authenticate('local', {
        failureRedirect:'/login',
        successRedirect: '/success',
        failureFlash:true,
    })(req,res,next)
});

routes.get('/success',checkAuthenticated ,(req,res)=>{
    res.render('success');
})
routes.get('/logout', (req,res)=>{
    req.logout();
    res.redirect('/login');
})

module.exports = routes;