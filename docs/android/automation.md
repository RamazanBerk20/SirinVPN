# Android automation intents

Automation apps such as Tasker or Automate can connect, disconnect and choose
the server by sending a broadcast to SirinVPN. Only apps you grant the
**connect and disconnect SirinVPN** permission
(`org.sirinvpn.permission.CONTROL_VPN`) can do this. It is a `dangerous`
permission: Android asks you before granting it, and you can revoke it in the
automation app's permission settings.

## Permission

Android can grant a permission only to an app that declares it in its own
manifest. An automation app that doesn't declare this one can't be granted it,
and its broadcasts are dropped; ask its developer to add it, or use an app you
build yourself. The app declares it, then asks for it at runtime or lets you
grant it in Android settings (**Apps › the app › Permissions › Additional
permissions**):

```xml
<uses-permission android:name="org.sirinvpn.permission.CONTROL_VPN" />
<queries><package android:name="org.sirinvpn.client" /></queries>
```

Install SirinVPN before granting it. On a development device you can grant it
from a computer to an app that lists it:

```sh
adb shell pm grant <automation.app.package> org.sirinvpn.permission.CONTROL_VPN
```

Without the permission, Android drops the broadcast before SirinVPN sees it.
Android's shell and apps you have not granted it cannot use these actions.

## Actions

Send a broadcast with the package set to `org.sirinvpn.client` (or the class
`org.sirinvpn.client.AutomationReceiver`). Android doesn't deliver a broadcast
that names no package to SirinVPN.

| Action | Extra | Effect |
| --- | --- | --- |
| `org.sirinvpn.action.CONNECT` | none | Connects to the Quick Settings server. Does nothing if that server is already connected or connecting. |
| `org.sirinvpn.action.DISCONNECT` | none | Disconnects and pauses automatic reconnection, like **Disconnect** in the app. |
| `org.sirinvpn.action.SELECT_SERVER` | `server` (string) | Makes that server the Quick Settings server: the one Connect, the tile and the widget use. Matches the server's exact name or its ID; nothing changes if no server or more than one matches. It doesn't disconnect: send CONNECT afterwards to switch an active connection. |

The Quick Settings server is set in **Settings › General › Quick Settings
server**. To switch to a server called Home VPS, send two broadcasts:

```text
action org.sirinvpn.action.SELECT_SERVER, package org.sirinvpn.client, string extra server = Home VPS
action org.sirinvpn.action.CONNECT,       package org.sirinvpn.client
```

In an app that holds the permission, such as Tasker's **Send Intent** or
Automate's **Broadcast send**, set the action, the package and Broadcast
Receiver as the target.

## Behavior and limits

- No result is returned. Check the app, the notification or the widget.
  Failures show there as they do for the tile: for example **VPN permission is
  needed** when another VPN app took over, or **Couldn’t connect**.
- Connect needs Android's VPN consent, which only you can give in SirinVPN.
  A broadcast cannot open the consent dialog.
- When Android's Always-on VPN controls SirinVPN, Disconnect is refused, as it
  is in the app.
- The actions work while the device is locked, after it has been unlocked once
  since starting. The notification's buttons still ask you to unlock.
- An app with this permission can disconnect the VPN. Grant it only to
  automation apps you trust.
