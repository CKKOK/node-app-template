import { builtinModules } from "module";

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
	var node = new LinkedListNode(data);
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
	var x = this.head;
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
	var node = this.head;
	while (node !== null) {
		handler(node.data);
		node = node.next;
	};
};

module.exports = {
    LinkedList
}