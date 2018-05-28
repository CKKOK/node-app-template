const config = require('../config');
const bcrypt = require('bcrypt');
const asyncf = require('../async');

function _expressSession(User) {
    
    return {
        sessionCheck: function(req, res, next) {
            if (req.cookies.user_sid) {
                if (!req.session.user) {
                    res.clearCookie('user_sid');
                };
            };
            next();
        },

        checkForAuth: function(req, res, next) {
            if (req.cookies.user_sid && req.session.user) {
                next();
            } else {
                res.json({message: 'Unauthorised access'});
                res.end();
            }
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
                req.session.user = result.user;
            };
            next();
        },
    
        login: async function (req, res, next) {
            let result = await User.authenticate(req.body.email, req.body.password);
            if (result.user) {
                req.session.user = result.user;
            } else {
                res.locals.loginMessage = result.message;
            };
            return next();
        },
    
        logout: function (req, res, next) {
            delete req.session.user;
            res.clearCookie('user_sid');
            next();
        },
    }
};

function _jwtExpressSession(User) {
    const jwt = require('jsonwebtoken');

    return {
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

        checkForAuth: function (req, res, next) {
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
                req.session.token = token;
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
                req.session.token = token;
            } else {
                res.locals.loginMessage = result.message;
            };
            return next();
        },
    
        logout: function (req, res, next) {
            delete req.session.token;
            next();
        },
    }
};

function _jwtCookies(User) {
    const jwt = require('jsonwebtoken');

    return {
        sessionCheck: function (req, res, next) {
            if (req.cookies.token) {
                jwt.verify(req.cookies.token, config.jwtSecret, (err, decodedToken) => {
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
    
        checkForAuth: function (req, res, next) {
            if (req.user) {
                next();
            } else {
                res.json({message: 'Unauthorised access'});
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
                res.cookie('token', token);
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
                res.cookie('token', token);
            } else {
                res.locals.loginMessage = result.message;
            };
            return next();
        },
    
        logout: function (req, res, next) {
            res.clearCookie('token');
            next();
        },
    }
};

function _passportJwt(User) {
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
        let result = await User.find(jwtPayload.name);
        if (result.user) {
            next(null, result.user);
        } else {
            next(result.message, false, {message: result.message});
        }
    });
    passport.use(jwtStrategy);

    return {
        passport: passport,
        
        sessionCheck: function(req, res, next) {next()},

        checkForAuth: passport.authenticate('jwt', {session: false}),
    
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
                res.cookie('token', token);
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
    }
};

function _passport(User) {

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

    return {
        passport: passport,

        sessionCheck: function (req, res, next) {
            next();
        },
        
        checkForAuth: function (req, res, next) {
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
                    return next();
                })
            } else {
                res.locals.registerMessage = result.message;
                next();
            };
        },
    
        login: passport.authenticate('local'),
    
        logout: function (req, res, next) {
            req.logout();
            next();
        },
    }

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
