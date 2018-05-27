module.exports = function(io){
    io.on('connection', (socket) => {

        socket.on('join', (data) => {
            console.log(data);
        });
    });
};

