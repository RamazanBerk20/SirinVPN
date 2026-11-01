package org.sirinvpn.client;

/** Test APK only: resends an automation broadcast from this package's separate UID, as Tasker would. */
public class AutomationRelay extends android.content.BroadcastReceiver {
    @Override public void onReceive(android.content.Context context, android.content.Intent intent) {
        String hardware=android.os.Build.HARDWARE;
        if(!hardware.equals("ranchu") && !hardware.equals("goldfish")) throw new SecurityException("Isolated emulator required");
        android.content.Intent forwarded=new android.content.Intent(intent.getStringExtra("action")).setPackage("org.sirinvpn.client");
        if(intent.hasExtra("server")) forwarded.putExtra("server",intent.getStringExtra("server"));
        context.sendBroadcast(forwarded);
    }
}
