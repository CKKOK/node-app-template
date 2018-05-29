const config = require('../config');
const TFA = require('../lib/2fa');
const User = require('./user').model;
const asyncf = require('../async');

module.exports = {
    create: async function (userId) {
        let secret = TFA.generateTFASecret();
        let [err, user] = await asyncf(User.findOneAndUpdate({_id: userId}, {TFASecret: secret}));
        if (err || !user) {
            return {secret: {}, imagelink: ''};
        } else {
            let imagelink = await TFA.generateTFAQRCode(secret);
            return {secret, imagelink};
        };
    },

    get: async function (userId) {
        let [err, user] = await asyncf(User.findOne({_id: userId}, 'TFAEnabled TFASecret'));
        if (err || !user.TFAEnabled || !user.TFASecret.base32) {
            return {secret: {}, imagelink: ''};
        } else {
            let imagelink = await TFA.generateTFAQRCode(user.TFASecret);
            return {secret: user.TFASecret, imagelink};
        }
    },

    update: async function (userId, newSecret) {
        let [err, user] = await asyncf(User.findOneAndUpdate({_id: userId}, {TFASecret: newSecret}));
        if (err || !user) {
            return {secret: {}, imagelink: ''};
        } else {
            let imagelink = TFA.generateTFAQRCode(newSecret);
            return {secret: newSecret, imagelink};
        };
    },

    delete: async function (userId) {
        let [err, user] = await asyncf(User.findOneAndUpdate({_id: userId}, {TFAEnabled: false, TFASecret: {}}));
        if (err || !user) {
            return {success: false, message: 'An error occurred in deleting the 2FA secret'};
        } else {
            return {success: true, message: '2FA secret removed'};
        }
    },

    verify: async function(userId, key) {
        let [err1, user] = await asyncf(User.findOne({_id: userId}, 'TFASecret'));
        let result = TFA.verify(user.TFASecret, key.toString());
        if (result === true) {
            let [err2, update] = await asyncf(User.findOneAndUpdate({_id: userId}, {TFAEnabled: true}));
        };
        return result;
    }
}