const config = require('../config');
const bcrypt = require('bcrypt');
const asyncf = require('../async');

function _expressSession(User) {
    function checkForAuth(req, res, next) {
        next();
    };

    function login(req, res) {
        let [err1, user] = await asyncf(User.findOne({email: email}).lean());
        let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (true === result) {
            delete user.password;
            return user;
        } else {
            return false;
        }
    };

    function logout(req, res) {
        delete req.session.user;
        delete req.session.authenticated;
        res.clearCookie('user_sid');
    };
};

function _jwtExpressSession(User) {
    const jwt = require('jsonwebtoken');

    function checkForAuth(req, res, next) {
        next();
    };

    function login(req, res) {
        let [err1, user] = await asyncf(User.findOne({email: email}).lean());
        let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (true === result) {
            let responseToken = {
                token: jwt.sign({
                    _id: user._id,
                    name: user.name,
                    email: user.email
                }, config.jwtSecret)
            };
            return responseToken;
        } else {
            return false;
        }
    };

    function logout(req, res) {
        delete req.session.token;
    };
};

function _jwtCookies(User) {
    const jwt = require('jsonwebtoken');
    function checkForAuth(req, res, next) {
        next();
    };

    function login(req, res) {

    };

    function logout(req, res) {
        res.clearCookie('token');
    };
};

function _passportJwt(User) {
    function checkForAuth(req, res, next) {
        next();
    };

    function login(req, res) {

    };

    function logout(req, res) {

    };
};

function _passport(User) {

    const passport = require('passport');
    const LocalStrategy = require('passport-local').Strategy;
    const localOptions = {
        usernameField: 'email',
        passwordField: 'password'
    };
    const localStrategy = new LocalStrategy(localOptions, async function(email, password, done) {
        let [err1, user] = await asyncf(User.findOne({email: email}).lean());
        let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (err1) {
            return done(err1);
        } else if (err2) {
            return done(err2);
        } else if (result) {
            return done(null, user);
        } else {
            return done(null, false, {message: 'Incorrect password'});
        };
    });
    passport.use(localStrategy);

    passport.serializeUser(function(user, done) {
        done(null, user._id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        })
    })

    function checkForAuth(req, res, next) {
        if (req.user) {
            next();
        } else {
            res.status(401).json({message: 'Unauthorised access'});
        };
    };

    function login(req, res) {

    };

    function logout(req, res) {
        req.logout();
    };
}

let toExport = null;

switch(config.authMethod) {
    case 'express-session':
        console.log('User authentication: express-session');
        toExport = _expressSession;
        break;
    case 'jwt-express-session':
        console.log('User authentication: jwt-express-session');    
        toExport = _jwtExpressSession;
        break;
    case 'jwt-cookies':
        console.log('User authentication: jwt-cookies');
        toExport = _jwtCookies;
        break;
    case 'passport-jwt':
        console.log('User authentication: passport-jwt');
        toExport = _passportJwt;
        break;
    case 'passport':
        console.log('User authentication: passport');
        toExport = _passport;
        break;
    default:
        console.log('User authentication library not set');
        break;
}

module.exports = toExport;
