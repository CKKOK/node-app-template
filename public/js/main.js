let token = null;

function setStyle(element, styles) {
    Object.assign(element.style, styles);
};

function setStyleAll(selector, styles) {
    var elements = document.querySelectorAll(selector);
    for (var i = 0; i < elements.length; i++) {
        Object.assign(elements[i].style, styles);
    };
};

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
