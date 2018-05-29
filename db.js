const config = require('./config');
const bcrypt = require('bcrypt');

// PostgreSQL
// const Sequelize = require('sequelize');
// const db = new Sequelize(config.db);

// MongoDB
const mongoose = require('mongoose');
const mongooseOptions = {
    reconnectTries: Number.MAX_VALUE,
    reconnectInterval: 500,
    poolSize: 10
};
mongoose.connect(config.db, mongooseOptions).then(
    () => {console.log('Database connected')},
    (err) => {console.log('Error connecting to database:', err)}
);
mongoose.Promise = global.Promise;
const db = mongoose.connection;
const Schema = mongoose.Schema;


module.exports = {mongoose, db, Schema};

