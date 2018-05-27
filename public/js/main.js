function sendData(opts) {
    var xhr = new XMLHttpRequest();

    if (opts.onLoad) {xhr.addEventListener('load', opts.onLoad)};
    if (opts.onError) {xhr.addEventListener('error', opts.onError)};

    xhr.open(opts.method, opts.url);
    if (opts.withCredentials) {xhr.withCredentials = opts.withCredentials};
    xhr.setRequestHeader('Csrf-Token', opts.token);
    if (opts.header) {xhr.setRequestHeader(opts.header[0], opts.header[1])};
    xhr.send(opts.data);
};

function handleSubmit(event) {
    event.preventDefault();
    var data = new FormData(document.getElementById('formLogin'));
    sendData({
        url: '/users/login',
        data: data,
        method: 'POST',
        onLoad: function(evt){
            if (this.responseText === 'Unauthorized') {
                console.log('Failed to login');
            } else {
                console.log(JSON.parse(this.responseText))
            };
        },
        onError: function(evt){console.log(evt)},
        // header: ['Content-Type', 'multipart/form-data; boundary=--loginFormBoundary'],
        withCredentials: true,
        token: document.querySelector('input[name="_csrf"]').value,
    });
}