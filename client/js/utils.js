// Helpers for setting CSS styles for single and multiple elements
// ===============================================================
function setStyle(element, styles) {
    Object.assign(element.style, styles);
};

function setStyleAll(selector, styles) {
    var elements = document.querySelectorAll(selector);
    for (var i = 0; i < elements.length; i++) {
        Object.assign(elements[i].style, styles);
    };
};


// Linked list implementation
// ==========================
function LinkedListNode(data) {
	this.data = data;
	this.prev = null;
	this.next = null;
};

function LinkedList() {
	this.__length = 0;
	this.head = null;
	this.tail = null;
};

LinkedList.prototype.addNode = function (data) {
	let node = new LinkedListNode(data);
	if (this.head === null) {
		this.head = node;
		this.tail = node;
	} else {
		this.tail.next = node;
		node.prev = this.tail;
		this.tail = node;
	};
	this.__length++;
	return node;
};

LinkedList.prototype.removeNode = function (data) {
	let x = this.head;
	while(x !== null && x.data !== data) {
		x = x.next;
	};
	if (x !== null) {
		this.deleteNode(x);
	};
};

LinkedList.prototype.deleteNode = function (node) {
	if (node.prev !== null) {
		node.prev.next = node.next;
	} else {
		this.head = node.next;
	}
	if (node.next !== null) {
		node.next.prev = node.prev;
	} else {
		this.tail = node.prev;
	}
	node.prev = null;
	node.next = null;
	this.__length--;
	return node;
};

LinkedList.prototype.forEach = function (handler) {
	let node = this.head;
	while (node !== null) {
		handler(node.data);
		node = node.next;
	};
};

// Helper for submitting AJAX forms
// ================================
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
