var socket = null;
var stompClient = null;

function connect() {
    socket = new SockJS('/ws-chat');
    stompClient = Stomp.over(socket);
    stompClient.connect({}, function (frame) {
        console.log('Connected: ' + frame);
        stompClient.subscribe('/topic/messages', function (message) {
            showMessage(JSON.parse(message.body));
        });
    });
}

function showMessage(msg) {
    var messages = document.getElementById('messages');
    var el = document.createElement('div');
    el.textContent = msg.from + ': ' + msg.text;
    messages.appendChild(el);
    messages.scrollTop = messages.scrollHeight;
}

document.addEventListener('DOMContentLoaded', function () {
    connect();

    var form = document.getElementById('chatForm');
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var from = document.getElementById('from').value;
        var text = document.getElementById('text').value;
        if (!stompClient) return;
        stompClient.send('/app/chat.send', {}, JSON.stringify({from: from, text: text}));
        document.getElementById('text').value = '';
    });
});
