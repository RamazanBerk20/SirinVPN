"""WireGuard peers in a disposable container; output contains public keys only."""
import base64
import json
import os
import subprocess
import sys


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=True).stdout


if sys.argv[1] == "prepare":
    assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
    assert os.path.exists("/.dockerenv")
    assert [entry["ifname"] for entry in json.loads(run("ip", "-j", "link"))] == ["lo"]
    keys = [base64.b64encode(os.urandom(32)) for _ in range(3)]
    public = [run("wg", "pubkey", data=key).decode().strip() for key in keys]
    run("ip", "link", "set", "lo", "up")
    run("ip", "netns", "add", "activity-client")
    for name in ["sirinvpn0", "activity0"]:
        run("ip", "link", "add", name, "type", "wireguard")
    for i, (name, port) in enumerate([("sirinvpn0", 51872), ("activity0", 51873)]):
        config = (f"[Interface]\nPrivateKey={keys[i].decode()}\nListenPort={port}\n"
                  f"[Peer]\nPublicKey={public[1-i]}\nAllowedIPs=198.18.0.{2-i}/32\n"
                  f"Endpoint=127.0.0.1:{51873-i}\n")
        if i == 0:
            config += f"[Peer]\nPublicKey={public[2]}\nAllowedIPs=198.18.0.3/32\n"
        run("wg", "setconf", name, "/dev/stdin", data=config.encode())
    # The client UDP socket stays in its birth namespace; its tunnel lives alone.
    run("ip", "link", "set", "activity0", "netns", "activity-client")
    for prefix, device, address, destination in [([], "sirinvpn0", 1, 2),
            (["-n", "activity-client"], "activity0", 2, 1)]:
        run("ip", *prefix, "link", "set", "lo", "up")
        run("ip", *prefix, "address", "add", f"198.18.0.{address}/32", "dev", device)
        run("ip", *prefix, "link", "set", device, "up")
        run("ip", *prefix, "route", "add", f"198.18.0.{destination}/32", "dev", device)
    print(json.dumps(public[1:]))
else:
    run("ip", "netns", "exec", "activity-client", "ping", "-c", "1", "-W", "5", "198.18.0.1")
