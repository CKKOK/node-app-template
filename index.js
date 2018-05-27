const config = require('./config');
const server = require('./server');

if (config.protocol === 'http') {

    const http = require('http').createServer(server);

    if (config.websocketsEnabled) {
        const io = require('socket.io')(http);
        const socketConfig = require('./lib/socket')(io);
    };

    http.listen(config.port, () => {
        console.log(`Http server started on port ${config.port}`);
    });

} else if (config.protocol === 'https') {
    const forceSSL = require('express-force-ssl');
    server.use(forceSSL);
    const fs = require('fs');
    const options = {
        key: fs.readFileSync('./https_certs/server.key'),
        cert: fs.readFileSync('./https_certs/server.crt'),
    };
    const https = require('https').createServer(options, server);

    if (config.websocketsEnabled) {
        const io = require('socket.io')(https);
        const socketConfig = require('./lib/socket')(io);
    };

    https.listen(config.portSecure, () => {
        console.log(`Https server started on port ${config.portSecure}`);
    });
    
};
