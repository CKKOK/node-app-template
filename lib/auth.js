const config = require('../config');
const bcrypt = require('bcrypt');
const asyncf = require('../async');

function _expressSession(User, server) {
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
    
        login: async function (req, res, next) {
            let [err1, user] = await asyncf(User.findOne({email: email}).lean());
            if (err1) {
                console.log('Error finding user ' + err1);
                return next();
            } else if (!user) {
                req.session.user = null;
                res.locals.loginResult = 'User not found';
                return next();
            };
            let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
            if (true === result) {
                delete user.password;
                req.session.user = user;
                res.locals.loginResult = 'Logged in';
                return next();
            } else if (err2) {
                console.log('Error comparing passwords ' + err2);
                return next();
            } else {
                res.locals.loginResult = 'Incorrect password';
                return next();
            }
        },
    
        logout: function (req, res, next) {
            delete req.session.user;
            res.clearCookie('user_sid');
            next();
        },
    }
};

function _jwtExpressSession(User, server) {
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
    
        login: async function (req, res, next) {
            let [err1, user] = await asyncf(User.findOne({email: email}).lean());
            if (err1) {
                console.log('Error finding user ' + err1);
                return next();
            } else if (!user) {
                req.session.token = null;
                res.locals.loginResult = 'User not found';
                return next();
            };
            let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
            if (true === result) {
                let token = jwt.sign({
                        _id: user._id,
                        name: user.name,
                        email: user.email
                    }, config.jwtSecret);
                req.session.token = token;
                res.locals.loginResult = 'Logged in';
                return next();
            } else if (err2) {
                console.log('Error comparing passwords ' + err2);
                return next();
            } else {
                res.locals.loginResult = 'Incorrect password';
                return next()
            };
        },
    
        logout: function (req, res, next) {
            delete req.session.token;
            next();
        },
    }
};

function _jwtCookies(User, server) {
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
    
        login: async function (req, res, next) {
            let [err1, user] = await asyncf(User.findOne({email: email}).lean());
            if (err1) {
                console.log('Error finding user ' + err1);
                return next();
            } else if (!user) {
                res.locals.loginResult = 'User not found';
                return next();
            };
            let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
            if (true === result) {
                let token = jwt.sign({
                        _id: user._id,
                        name: user.name,
                        email: user.email
                    }, config.jwtSecret);
                res.cookie('token', token);
                res.locals.loginResult = 'Logged in';
                next();
            } else if (err2) {
                console.log('Error comparing passwords ' + err2);
                next();
            } else {
                res.locals.loginResult = 'Incorrect password';
                return next();
            }
        },
    
        logout: function (req, res, next) {
            res.clearCookie('token');
            next();
        },
    }
};

function _passportJwt(User, server) {
    const jwt = require('jsonwebtoken');
    const passport = require('passport');
    const passportJwt = require('passport-jwt');
    const ExtractJwt = passportJwt.ExtractJwt;
    const JwtStrategy = passportJwt.Strategy;
    const jwtOptions = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: config.jwtSecret
    };
    const jwtStrategy = new JwtStrategy(jwtOptions, async function(jwtPayload, next) {
        console.log('payload received', jwtPayload);
        // find the user with id corresponding to jwtPayload.id here from the database
        // then if the user exists, pass it into the next function as the 2nd parameter
        let [err1, user] = await asyncf(User.findOne({email: jwtPayload.email}).lean());
        // let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (user) {
            next(null, user);
        } else {
            next(null, false);
        }
    });
    passport.use(jwtStrategy);

    passport.serializeUser(function(user, done) {
        done(null, user._id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        })
    })

    server.use(passport.initialize());
    server.use(passport.session());

    return {
        sessionCheck: function (req, res, next) {
            next();
        },

        checkForAuth: function (req, res, next) {
            next();
        },
    
        login: passport.authenticate('jwt'),
    
        logout: function (req, res, next) {
            req.logout();
            next();
        },
    }
};

function _passport(User, server) {

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

    server.use(passport.initialize());
    server.use(passport.session());

    return {
        passport: passport,

        sessionCheck: function (req, res, next) {
            next();
        },
        
        checkForAuth: function (req, res, next) {
            if (req.user) {
                next();
            } else {
                res.status(401).json({message: 'Unauthorised access'});
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
