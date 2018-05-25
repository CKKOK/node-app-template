const config = require('./config');
const bcrypt = require('bcrypt');

// PostgreSQL
// const Sequelize = require('sequelize');
// const db = new Sequelize(config.db);

// MongoDB
const mongoose = require('mongoose');
mongoose.connect(config.db);
mongoose.Promise = global.Promise;
const db = mongoose.connection;
const Schema = mongoose.Schema;


module.exports = {mongoose, db, Schema};

