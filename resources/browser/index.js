

let TEST_SRC_URL = "ws://127.0.0.1:10020"
let TEST_DST_URL = "ws://127.0.0.1:10015"
let DEFAULT_COMMAND_URL = "ws://127.0.0.1:12345"

let eleInputCommand = document.getElementById("input-command")
let eleButtonStart = document.getElementById("btn-start")
let eleTextConnection = document.getElementById("text-conn")
let eleTextConnectionStatus = document.getElementById("text-conn-status")


function setTextConnection(url) {
    eleTextConnection.textContent = url
}

let CONN_STATUS_CONNECTING = 0
let CONN_STATUS_OK = 1
let CONN_STATUS_CLOSED = 2

function setTextConnectionStatus(status) {
    if (status === CONN_STATUS_CONNECTING) {
        eleTextConnectionStatus.style.color = "blue"
        eleTextConnectionStatus.textContent = "CONNECTING"
        eleButtonStart.disabled = true
    }
    else if (status === CONN_STATUS_OK) {
        eleTextConnectionStatus.style.color = "green"
        eleTextConnectionStatus.textContent = "OK"
        eleButtonStart.disabled = true
    }
    else if (status === CONN_STATUS_CLOSED) {
        eleTextConnectionStatus.style.color = "red"
        eleTextConnectionStatus.textContent = "CLOSED"
        eleButtonStart.disabled = false
    }
}

function main() {
    console.log("Hello world")
    eleInputCommand.value = DEFAULT_COMMAND_URL
    eleButtonStart.onclick = function (_e) {
        let url = eleInputCommand.value
        let _c = new CommandConnection(url)
    };
}

class ProxyConnection {
    constructor() {
        this.dst_ws = null
        this.src_ws = null
    }

    run(src_url, dst_url) {
        console.log("src " + src_url)
        console.log("dst " + dst_url)

        let proxy = this

        this.dst_ws = null
        this.src_ws = new WebSocket(src_url)
        // buffer for src
        // Because dst will only start connection after src is opened, 
        // there is no need for dst buffer
        this.src_buf = []


        // use array buffer because we dont process any of the binary data
        this.src_ws.binaryType = "arraybuffer";

        this.src_ws.onopen = function (_ev) {
            // src websocket connection established
            console.log("src open")

            proxy.dst_ws = new WebSocket(dst_url)
            proxy.dst_ws.binaryType = "arraybuffer"

            proxy.dst_ws.onopen = function (_ev) {
                console.log("dstn open")
                // check buffer to see if there are any message for dst when it's opening
                if (proxy.src_buf.length > 0) {
                    proxy.src_buf.forEach(function (data, _) {
                        console.log("Buffered data size: " + data.byteLength);
                        proxy.dst_ws.send(data)
                    })
                    proxy.src_buf = []
                }
            }

            proxy.dst_ws.onclose = function (ev) {
                console.log("dstn close")
                if (proxy.src_ws && proxy.src_ws.readyState === WebSocket.OPEN) {
                    proxy.src_ws.close()
                }
            }

            proxy.dst_ws.onmessage = function (ev) {
                if (proxy.src_ws) {
                    if (typeof ev.data === String) {
                        // console.log("dstn send a string message of " + ev.data.length + " bytes to src.")
                    }
                    else {
                        // console.log("dstn send an arraybuffer message of " + ev.data.byteLength + " bytes to src.")
                    }
                    if (proxy.src_ws.readyState == WebSocket.OPEN) {
                        proxy.src_ws.send(ev.data)
                    } else {
                        console.log("Message received on dst, but src's readyState is " + proxy.src_ws.readyState)
                        proxy.dst_ws.close()
                    }
                }
                else {
                    console.log("dstn try to send message but src is null.")
                    proxy.dst_ws.close()
                }
            }

            proxy.dst_ws.onerror = function (ev) {
                console.log("dstn error")
                if (proxy.src_ws && proxy.src_ws.readyState === WebSocket.OPEN) {
                    proxy.src_ws.close()
                }
            }
        }

        proxy.src_ws.onclose = function (ev) {
            console.log("src close")
            if (proxy.dst_ws && proxy.dst_ws.readyState === WebSocket.OPEN) {
                proxy.dst_ws.close()
            }
        }

        proxy.src_ws.onmessage = function (ev) {
            if (proxy.dst_ws) {
                if (typeof ev.data === String) {
                    // console.log("src send a string message of " + ev.data.length + " bytes to dst.")
                }
                else {
                    // console.log("src send an arraybuffer message of " + ev.data.byteLength + " bytes to dst.")
                }

                if (proxy.dst_ws.readyState == WebSocket.OPEN) {
                    // already connected, clear the buffer
                    if (proxy.src_buf.length > 0) {
                        console.log("Clearing the buffer")
                        proxy.src_buf.forEach(function (data, index) {
                            console.log("Buffered data size: " + data.byteLength);
                            proxy.dst_ws.send(data)
                        })
                        proxy.src_buf = []
                    }

                    proxy.dst_ws.send(ev.data)
                }
                else if (proxy.dst_ws.readyState == WebSocket.CONNECTING) {
                    // still connecting, store message into buffer
                    proxy.src_buf.push(ev.data)
                    console.log("Into the buffer")
                }
                else {
                    // connection dead
                    console.log("src received message but dst is closed or closing.")
                    proxy.src_ws.close()
                }
            }
            else {
                console.log("src try to send message but dst is null.")
            }
        }

        proxy.src_ws.onerror = function (ev) {
            console.log("src error")
            if (proxy.dst_ws && proxy.dst_ws.readyState === WebSocket.OPEN) {
                proxy.dst_ws.close()
            }
        }
    }
}

class CommandConnection {
    constructor(url) {
        console.log("Creating command websocket to " + url)
        this.ws = new WebSocket(url)
        this.ws.onopen = function (ev) {
            console.log("Command websocket established")
            setTextConnectionStatus(CONN_STATUS_OK)
        }
        this.ws.onmessage = function (ev) {
            let string_data = ev.data
            console.log("Command: " + string_data)
            let data = JSON.parse(string_data)
            let proxyConn = new ProxyConnection()
            proxyConn.run(data.src, data.dst)
        }
        this.ws.onclose = function (ev) {
            setTextConnectionStatus(CONN_STATUS_CLOSED)
        }
        setTextConnection(url)
        setTextConnectionStatus(CONN_STATUS_CONNECTING)
    }
}

main()