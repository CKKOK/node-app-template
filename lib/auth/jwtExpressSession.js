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

const jwt = require('jsonwebtoken');

module.exports = {
    sessionCheck: function (req, res, next) {
        if (req.session.token) {
            jwt.verify(req.session.token, config.jwtSecret, (err, decodedToken) => {
                if (err) {
                    req.user = undefined;
                } else {
                    req.user = decodedToken;
                };
                next();
            });
        } else {
            req.user = undefined;
            next();
        }
    },

    require: function (req, res, next) {
        if (req.user) {
            next();
        } else {
            res.json({message: 'Unauthorised access'});
            res.end();
        };
    },

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
            req.session.user = result.user;
            req.session.token = token;
        };
        next();
    },

    verification: async function(req, res, next) {
        if (config.userVerificationRequired === true) {
            let verificationString = uuid();
            let result = await User.setVerificationString(req.session.user._id, verificationString);
            let mailOptions = {
                from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
                to: req.session.user.email,
                subject: 'User Verification - ' + req.session.user.name,
                text: 'Please view this email in a HTML-capable mail client',
                html: generateHTMLVerificationEmail(req.session.user._id, req.session.user.name, verificationString)
            };
            mailer.send(mailOptions);
        };
        next();
    },

    login: async function (req, res, next) {
        let result = await User.authenticate(req.body.email, req.body.password);
        if (result.message === 'Logged in') {
            let token = jwt.sign({
                _id: result.user._id,
                name: result.user.name,
                email: result.user.email
            }, config.jwtSecret, {
                expiresIn: config.authJWTExpirationTime
            });
            req.session.user = result.user;
            req.session.token = token;
        } else {
            res.locals.loginMessage = result.message;
        };
        return next();
    },

    logout: function (req, res, next) {
        delete req.session.token;
        delete req.session.user;
        next();
    },
};