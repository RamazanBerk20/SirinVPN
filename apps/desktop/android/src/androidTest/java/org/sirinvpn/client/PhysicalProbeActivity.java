package org.sirinvpn.client;

/** Keeps the explicitly authorized test UID foreground for OS packet checks. */
public final class PhysicalProbeActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        if (!getIntent().getBooleanExtra("authorized_acceptance", false)) {
            finish();
            return;
        }
        android.widget.TextView label = new android.widget.TextView(this);
        label.setText("SirinVPN network acceptance\nSynthetic probes only");
        label.setTextSize(22);
        label.setPadding(32, 64, 32, 32);
        setContentView(label);
    }
}
