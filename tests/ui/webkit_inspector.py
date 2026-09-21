"""Small client for the local WebKitGTK inspector used by native UI checks."""
import json
import re
import time
from urllib.request import urlopen
import websocket


def wait_for(check, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, websocket.WebSocketException):
            pass
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for the native app")


class Inspector:
    def __init__(self, port=9236):
        def target_url():
            with urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                match = re.search(r"/socket/\d+/\d+/WebPage", response.read().decode())
                return match and f"ws://127.0.0.1:{port}" + match[0]
        self.socket = websocket.create_connection(wait_for(target_url), timeout=10)
        self.sequence = 0
        while True:
            event = json.loads(self.socket.recv())
            if event.get("method") == "Target.targetCreated":
                target = event["params"]["targetInfo"]
                if target["type"] == "frame":
                    self.target = target["targetId"]
                    break
        wait_for(lambda: self.evaluate("Boolean(window.__TAURI_INTERNALS__)"))

    def command(self, method, parameters):
        self.sequence += 1
        message_id = self.sequence
        self.socket.send(json.dumps({"id": message_id, "method": "Target.sendMessageToTarget", "params": {
            "targetId": self.target, "message": json.dumps({"id": message_id,
                "method": method, "params": parameters})}}))
        while True:
            event = json.loads(self.socket.recv())
            if event.get("method") != "Target.dispatchMessageFromTarget":
                continue
            response = json.loads(event["params"]["message"])
            if response.get("id") != message_id:
                continue
            assert not response.get("error"), response.get("error")
            result = response["result"]
            assert not result.get("wasThrown"), result
            return result.get("result", result)

    def evaluate(self, expression):
        return self.command("Runtime.evaluate", {"expression": expression, "returnByValue": True}).get("value")

    def invoke(self, command, arguments=None, error=False):
        promise = self.command("Runtime.evaluate", {"expression": "window.__TAURI_INTERNALS__.invoke(" +
            json.dumps(command) + ", " + json.dumps(arguments or {}) + ").then(" +
            "value => ({value}), reason => ({error:String(reason)}))", "returnByValue": False})
        result = self.command("Runtime.awaitPromise", {"promiseObjectId": promise["objectId"], "returnByValue": True})["value"]
        if error:
            assert "error" in result, result
            return result["error"]
        assert "error" not in result, result
        return result.get("value")

    def close(self):
        self.socket.close()
