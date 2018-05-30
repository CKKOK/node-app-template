const config = require('../../config');
const bcrypt = require('bcrypt');
const asyncf = require('../../async');
const uuid = require('uuid-v4');
const mailer = require('../../lib/mail');
const User = require('../../models/user');

function generateHTMLVerificationEmail(id, name, key){
    let url = config.serverDomain + '/users/verify?key='+key+'&id='+id;
    let result = '<div>Thanks for registering, ' + name + '! To verify your account, please go to the following link:</div> \
                  <div style="width:11em;height:2em;line-height:2em;text-align:center;background-color:blue;color:white;border-radius:8px">\
                  <a href="'+url+'" style="text-decoration:none;color:white;font-size:1em">Verify now</a></div>'
    return result;
};

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const localOptions = {
    usernameField: 'email',
    passwordField: 'password'
};

const localStrategy = new LocalStrategy(localOptions, async function(email, password, done) {
    let [err1, user] = await asyncf(User.model.findOne({email: email}).lean());
    if (err1) {
        return done(err1);
    } else if (!user) {
        return done(null, false, {message: 'User not found'});
    };
    let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
    if (err2) {
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
    User.model.findById(id, function(err, user) {
        done(err, user);
    })
})

module.exports = {
    passport: passport,

    sessionCheck: function (req, res, next) {
        next();
    },
    
    require: function (req, res, next) {
        if (req.isAuthenticated()) {
            next();
        } else {
            res.send('Unauthorized');
            res.end();
        }
    },

    register: async function(req, res, next) {
        let result = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: req.body.password
        });
        if (result.message === 'User created') {
            req.logIn(result.user, (err) => {
                if (err) return next(err);
                req.user = result.user;
                return next();
            });
        } else {
            res.locals.registerMessage = result.message;
            next();
        };
    },

    verification: async function(req, res, next) {
        if (config.userVerificationRequired === true) {
            let verificationString = uuid();
            let result = await User.setVerificationString(req.user._id, verificationString);
            let mailOptions = {
                from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
                to: req.user.email,
                subject: 'User Verification - ' + req.user.name,
                text: 'Please view this email in a HTML-capable mail client',
                html: generateHTMLVerificationEmail(req.user._id, req.user.name, verificationString)
            };
            mailer.send(mailOptions);
        };
        next();
    },

    login: passport.authenticate('local'),

    logout: function (req, res, next) {
        req.logout();
        next();
    },
};
