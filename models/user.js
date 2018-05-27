const config = require('../config');
const { mongoose, db, Schema } = require('../db');
const bcrypt = require('bcrypt');
const asyncf = require('../async');

const UserSchema = new Schema({
    name: {
        type: String,
        trim: true,
        required: [true, 'Name required']
    },
    email: {
        type: String,
        unique: true,
        trim: true,
        required: [true, 'Email required']
    },
    password: {
        type: String,
        required: [true, 'Password required']
    },
    verified: {
        type: Boolean,
        required: true,
        default: false
    }
});

const UserVerificationSchema = new Schema({
    verificationString: {
        type: String,
        trim: true,
        required: true
    },
    userId: {
        type: Schema.Types.ObjectId,
        required: true
    }
});

const User = mongoose.model('users', UserSchema);
const Verify = mongoose.model('verification', UserVerificationSchema);

// Passport JWT Authentication
// =============================
const jwt = require('jsonwebtoken');
// const passport = require('passport');
// const passportJwt = require('passport-jwt');
// const ExtractJwt = passportJwt.ExtractJwt;
// const JwtStrategy = passportJwt.Strategy;
// const jwtOptions = {
//     jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
//     secretOrKey: config.jwtSecret
// };
// const jwtStrategy = new JwtStrategy(jwtOptions, async function(jwtPayload, next) {
//     console.log('payload received', jwtPayload);
//     // find the user with id corresponding to jwtPayload.id here from the database
//     // then if the user exists, pass it into the next function as the 2nd parameter
//     next(null, false);
// });
// passport.use(jwtStrategy);
// ====================================================================================

// Passport Local Authentication
// ====================
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const localOptions = {
    usernameField: 'email',
    passwordField: 'password'
};
const localStrategy = new LocalStrategy(localOptions, async function(email, password, done) {
    let [err1, user] = await asyncf(User.findOne({email: email}).lean());
    if (user === null) {
        return done(null, false, {message: 'User not found'});
    };
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
// ======================================================================================


passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    })
})



module.exports = {
    model: User,

    passport: passport,

    create: async function (user) {
        let [err1, password] = await asyncf(bcrypt.hash(user.password, config.salt));
        let [err2, result] = await asyncf(User.create({
            name: user.name,
            email: user.email,
            password: password
        }));
        return result;
    },

    find: async function (name) {
        let [err, result] = await asyncf(User.findOne({name: name}));
        return result;
    },

    update: async function (name, email, password) {
        let [err1, password] = await asyncf(bcrypt.hash(password, config.salt));
        let newUser = {
            name: name,
            email: email,
            password: password
        }
        let [err2, result] = await asyncf(User.findOneAndUpdate({name: name}, newUser, {new: true}));
        return result;
    },

    delete: async function (name) {
        let [err, result] = await asyncf(User.findOneAndRemove({name: name}));
        return result;
    },

    authenticate: async function (email, password) {
        let [err1, user] = await asyncf(User.findOne({email: email}).lean());
        let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (true === result) {
            // Express Session Authentication
            // ==============================
            // delete user.password;
            // return user;

            // JWT Authentication
            // ==================
            // let responseToken = {
            //     token: jwt.sign({
            //         _id: user._id,
            //         name: user.name,
            //         email: user.email
            //     }, config.jwtSecret)
            // };
            // return responseToken;
        } else {
            return false;
        }
    }
};
