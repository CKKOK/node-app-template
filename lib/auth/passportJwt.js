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
}

const jwt = require('jsonwebtoken');
const passport = require('passport');
const passportJwt = require('passport-jwt');
// const ExtractJwt = passportJwt.ExtractJwt;
const JwtStrategy = passportJwt.Strategy;

function fromCookie(req) {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['token'];
    };
    return token;
};

const jwtOptions = {
    // jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    jwtFromRequest: fromCookie,
    secretOrKey: config.jwtSecret
};

const jwtStrategy = new JwtStrategy(jwtOptions, async function(jwtPayload, next) {
    let result = await User.find({name: jwtPayload.name});
    if (result.user) {
        next(null, result.user);
    } else {
        next(result.message, false, {message: result.message});
    }
});

passport.use(jwtStrategy);

module.exports = {
    passport: passport,
    
    sessionCheck: function(req, res, next) {next()},

    require: passport.authenticate('jwt', {session: false}),

    register: async function(req, res, next) {
        let result = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: req.body.password
        });
        if (result.message != 'User created') {
            res.locals.registerMessage = result.message;
        } else {
            let token = jwt.sign({
                _id: result.user._id,
                name: result.user.name,
                email: result.user.email
            }, config.jwtSecret, {
                expiresIn: config.authJWTExpirationTime
            });
            req.user = result.user;
            res.cookie('token', token);
        };
        next();
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

    login: async function(req, res, next) {
        let result = await User.authenticate(req.body.email, req.body.password);
        if (result.message === 'Logged in') {
            let token = jwt.sign({
                _id: result.user._id,
                name: result.user.name,
                email: result.user.email
            }, config.jwtSecret, {
                expiresIn: config.authJWTExpirationTime
            });
            res.cookie('token', token);
        } else {
            res.locals.loginMessage = result.message;
        };
        return next();
    },

    logout: function (req, res, next) {
        req.logout();
        res.clearCookie('token');
        next();
    },
};