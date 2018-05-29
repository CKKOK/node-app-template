module.exports = function(io){
    io.on('connection', (socket) => {

        socket.on('join', (joinMessage) => {
            console.log(joinMessage);
        });

        socket.on('message', (message) => {
            console.log(message);
        });

        socket.on('customEvent', (eventData) => {

        })

        socket.on('disconnect', () => {

        })
    });
};

