const config = require('./config');
const redis = require('redis');
const redisClient = redis.createClient();
const express = require('express');

// const viewEngine = require('ejs-locals');
const viewEngine = require('express-handlebars');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const redisStore = require('connect-redis')(session);
const logger = require('morgan');
const path = require('path');
const server = express();
const forceSSL = require('express-force-ssl');
const csrf = require('csurf');
const csrfProtection = csrf({cookie: true});

// Enable request logging
server.use(logger('dev'));

// Force the use of https
// server.use(forceSSL);

// Enables overriding of http verbs for supporting PUT/PATCH and DELETE requests from older clients
server.use(methodOverride('_method'));

server.use(bodyParser.json());
server.use(bodyParser.urlencoded({
    extended: true
}));
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

// Cross Site Resource Forgery Protection
server.use(csrfProtection);

// Set up view engine and static asset paths
server.set('views', path.join(__dirname, 'views'));

// Use EJS
// server.engine('ejs', viewEngine);
// server.set('view engine', 'ejs');

// Use Handlebars
server.engine('handlebars', viewEngine.create({
    defaultLayout: 'default'
}).engine);
server.set('view engine', 'handlebars');

// Configure path to static assets
server.use(express.static(path.join(__dirname, 'public')));

// Check if this session contains an authenticated user
server.use((req, res, next) => {
    if (req.cookies.user_sid) {
        if (req.session.user) {
            req.session.authenticated = true;
        } else {
            res.clearCookie('user_sid');
        };
    };
    next();
});

// Routers
const rootRouter = require('./controllers/root');
const users = require('./controllers/users');

server.use('/', rootRouter);
server.use('/users', users);

module.exports = server;
