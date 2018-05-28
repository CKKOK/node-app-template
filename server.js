const config = require('./config');

const redis = require('redis');
const redisClient = redis.createClient();
const express = require('express');

// const viewEngine = require('ejs-locals');
const viewEngine = require('express-handlebars');

// const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');

// JWT Authentication
// const jwt = require('jsonwebtoken');


// Express Session Authentication
const session = require('express-session');
const redisStore = require('connect-redis')(session);

const logger = require('morgan');
const path = require('path');
const server = express();

const csrf = require('csurf');
const csrfProtection = csrf({cookie: true});

// Enable request logging
server.use(logger('dev'));

// Enables overriding of http verbs for supporting PUT/PATCH and DELETE requests from older clients
server.use(methodOverride('_method'));

// server.use(bodyParser.json());
// server.use(bodyParser.urlencoded({
//     extended: true
// }));
server.use(express.json());
server.use(express.urlencoded({extended: true}));
server.use(cookieParser());

// Set up express-session
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

// const passport = require('./models/user').passport;
// server.use(passport.initialize());
// server.use(passport.session());
const User = require('./models/user');
const auth = require('./lib/auth')(User);

// Cross Site Resource Forgery Protection
server.use(csrfProtection);

// Set up view engine and static asset paths
server.set('views', path.join(__dirname, 'views'));

// Use EJS
// server.engine('ejs', viewEngine);
// server.set('view engine', 'ejs');

// Use Handlebars
server.engine('hbs', viewEngine.create({
    extname: '.hbs',
    defaultLayout: 'default',
    partialsDir: path.join(__dirname, 'views', 'partials'),
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
}).engine);
server.set('view engine', 'hbs');

// Configure path to static assets
server.use(express.static(path.join(__dirname, 'public')));

if (config.authMethod === 'passport-jwt' || config.authMethod === 'passport') {
    server.use(auth.passport.initialize());
    server.use(auth.passport.session());
}

server.use(auth.sessionCheck);

// WebSockets Configuration: Pass the status on to the application level to cascade down to the response level
// ===========================================================================================================
server.locals.websocketsEnabled = config.websocketsEnabled;

// Routers
const root = require('./controllers/root');
const users = require('./controllers/users');
const api = require('./api/v1/api');

server.use('/', root);
server.use('/users', users);
server.use('/api/v1', api);

module.exports = server;
