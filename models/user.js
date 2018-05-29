const config = require('../config');
const { mongoose, db, Schema } = require('../db');
const bcrypt = require('bcrypt');
const asyncf = require('../async');
const TFA = require('../lib/2fa');

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
    isVerified: {
        type: Boolean,
        required: true,
        default: false
    },
    profile: {
        type: String,
        required: false,
        default: ''
    },
    profilePic: {
        type: String,
        required: false,
        default: ''
    },
    TFAEnabled: {
        type: Boolean,
        required: true,
        default: false
    },
    TFASecret: {
        type: Schema.Types.Mixed,
        required: false,
        default: {}
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

module.exports = {
    model: User,

    create: async function (user) {
        let [err1, password] = await asyncf(bcrypt.hash(user.password, config.salt));
        if (err1) {
            return {user: null, message: new Error(err1)};
        };
        let [err2, dbResult] = await asyncf(User.create({
            name: user.name,
            email: user.email,
            password: password
        }));
        if (err2) {
            return {user: null, message: new Error(err2)};
        };
        let createdUser = {
            _id: dbResult._id,
            name: dbResult.name,
            email: dbResult.email
        };
        return {user: createdUser, message: 'User created'};
    },

    find: async function (searchOpt) {
        let [err, result] = await asyncf(User.findOne(searchOpt));
        return {user: result, message: err};
    },

    update: async function (name, email, password) {
        let [err1, password] = await asyncf(bcrypt.hash(password, config.salt));
        if (err1) {return {user: null, message: err1}};
        let newUser = {
            name: name,
            email: email,
            password: password
        }
        let [err2, result] = await asyncf(User.findOneAndUpdate({name: name}, newUser, {new: true}));
        if (err2) {return {user: null, message: err2}};
        return {user: result, message: 'User updated'};
    },

    delete: async function (name) {
        let [err, result] = await asyncf(User.findOneAndRemove({name: name}));
        return {user: result, message: err};
    },

    authenticate: async function (email, password) {
        let [err1, user] = await asyncf(User.findOne({email: email}).lean());
        if (err1) {
            return {user: null, message: new Error(err1)}
        } else if (!user) {
            return {user: null, message: 'User not found'}
        }
        let [err2, result] = await asyncf(bcrypt.compare(password, user.password));
        if (true === result) {
            delete user.password;
            return {user: user, message: 'Logged in'};
        } else if (err2) {
            return {user: null, message: new Error(err2)};
        } else {
            return {user: null, message: 'Incorrect password'}
        }
    },

    verifyAccount: async function (userId, verificationString) {
        let [err1, task] = await asyncf(Verify.findOne({userId: userId}));
        if (task.verificationString === verificationString) {
            let [err2, task] = await asyncf(Verify.findOneAndDelete({userId: userId}));
            let [err3, user] = await asyncf(User.findOneAndUpdate({_id: userId}, {isVerified: true}));
            return user;
        } else {
            return false;
        };
    },

    setVerificationString: async function(userId, verificationString) {
        let [err1, result] = await asyncf(Verify.findOneAndUpdate({userId: userId}, {verificationString: verificationString}, {upsert: true}));
        return result;
    },

};
