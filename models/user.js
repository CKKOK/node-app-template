const config = require('../config');
const { mongoose, db, Schema } = require('../db');
const bcrypt = require('bcrypt');
const asyncf = require('../async');

const UserSchema = new Schema({
    name: {
        type: String,
        required: [true, 'Name required']
    },
    email: {
        type: String,
        required: [true, 'Email required']
    },
    password: {
        type: String,
        required: [true, 'Password required']
    }
})

const User = mongoose.model('users', UserSchema);

module.exports = {
    model: User,

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
            delete user.password;
            return user;
        } else {
            return false;
        }
    }
};
