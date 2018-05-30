const config = require('./config');
const express = require('express');
const logger = require('morgan');
const path = require('path');
const server = express();

// Environment configuration
// =========================
server.set('env', config.serverEnv);
config.serverDomain = config.protocol + '://' + config.serverDomain + ':' + (config.protocol === 'http' ? config.port : config.portSecure);

// Cross-Site Resource Forgery
// ===========================
const csrf = require('csurf');
const csrfProtection = csrf({cookie: true});

// Server logging
// ==============
server.use(logger('dev'));

const methodOverride = require('method-override');
server.use(methodOverride('_method'));

// Parsing of cookies, application/x-www-form-urlencoded, and json data
// ====================================================================
server.use(express.json());
server.use(express.urlencoded({extended: true}));
const cookieParser = require('cookie-parser');
server.use(cookieParser());

// Parsing of multipart/form-data for AJAX form submissions
// ========================================================
const multer = require('multer');
const upload = multer();
server.use(upload.array());

if (config.authMethod === 'express-session' || config.authMethod === 'jwt-express-session') {
    const session = require('express-session');
    const redis = require('redis');
    const redisClient = redis.createClient(6379, 'localhost'); 
    const redisStore = require('connect-redis')(session);
    let redisErrorThrown = false;
    redisClient.on('error', (err) => {
        if (!redisErrorThrown){
            console.log('Redis client error:\n===================\n', err);
            redisErrorThrown = true;
        }
    });
    redisClient.get('test', (err, res) => {
        console.log('Redis server running')
    });

    server.use(session({
        key: 'user_sid',
        secret: '12345',
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 600000
        },
        store: new redisStore({
            host: 'localhost',
            port: 6379,
            client: redisClient,
            ttl: 260
        })
    }));
    console.log('Session running');
}


// Cross Site Resource Forgery Protection
server.use(csrfProtection);
server.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
})

// Set up view engine and static asset paths
server.set('views', path.join(__dirname, 'views'));

// View Engine: EJS
// ================
// const viewEngine = require('ejs-locals');
// server.engine('ejs', viewEngine);
// server.set('view engine', 'ejs');

// View Engine: Handlebars
// =======================
const viewEngine = require('express-handlebars');
server.engine('hbs', viewEngine.create({
    extname: '.hbs',
    defaultLayout: 'default',
    partialsDir: path.join(__dirname, 'views', 'partials'),
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
}).engine);
server.set('view engine', 'hbs');

// Configure path to static assets
server.use(express.static(path.join(__dirname, 'client')));

// User authentication
// ===================
const User = require('./models/user');
const auth = require('./lib/auth')(User);

// Initializing passport
// =====================
if (config.authMethod === 'passport-jwt' || config.authMethod === 'passport') {
    server.use(auth.passport.initialize());
    server.use(auth.passport.session());
}

// Non-terminating for an authenticated user
// Use auth.require for a terminating check, e.g. to protect API access.
// =====================================================================
server.use(auth.sessionCheck);

// WebSockets Configuration: Pass the status on to the application level to cascade down to the response level
// ===========================================================================================================
server.locals.websocketsEnabled = config.websocketsEnabled;
server.locals.TwoFactorAuthRequired = config.TwoFactorAuthRequired;

// Setup webpack
// =============
if (config.webpackEnabled === true) {
    console.log('Booting up webpack');
    const webpack = require('webpack');
    const webpackDevMiddleware = require('webpack-dev-middleware');
    const webpackHotMiddleware = require('webpack-hot-middleware');
    const webpackConfig = require('./webpack.config');
    const compiler = webpack(webpackConfig);
    server.use(webpackDevMiddleware(compiler, {
        noInfo: true,
        stats: {
            colors: true
        }
    }));
    server.use(webpackHotMiddleware(compiler));
};

// Routers
const root = require('./controllers/root');
const users = require('./controllers/users');
const api = require('./api/v1/api');

server.use('/', root);
server.use('/users', users);
server.use('/api/v1', api);

// Rendering of error pages, e.g. 404
// ==================================
const createError = require('http-errors');

server.use((req, res, next) => {
    next(createError(404));
});
  
server.use((err, req, res, next) => {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(err.status || 500);
    res.render('error');
});

module.exports = server;
