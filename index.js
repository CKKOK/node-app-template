const config = require('./config');
const https = require('https');
const http = require('http');
const fs = require('fs');
const options = {};
const server = require('./server');

server.listen(config.port, () => {console.log(`Server started on port ${config.port}`)});