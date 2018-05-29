function handleSubmit(event) {
    event.preventDefault();
    var data = new FormData(document.getElementById('formLogin'));
    sendData({
        url: '/users/login',
        data: data,
        method: 'POST',
        onLoad: function(evt){
            console.log(this.responseText);
            if (this.responseText === 'Unauthorized') {
                console.log('Failed to login');
            } else {
                var result = JSON.parse(this.responseText);
                if (result.message === 'logged in') {
                    window.location.href = "http://localhost:3000";
                }
            };
        },
        onError: function(evt){console.log(evt)},
        withCredentials: true,
        token: document.querySelector('input[name="_csrf"]').value,
    });
};

// document.getElementById('btnSubmitLogin').addEventListener('click', handleSubmit);