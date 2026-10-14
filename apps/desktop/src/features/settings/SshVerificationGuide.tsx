import { CopyButton } from "../../components/CopyButton";

const command =
  'for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -l -E sha256 -f "$key"; done';

export function SshVerificationGuide({
  confirmation = "checkbox",
}: {
  confirmation?: "checkbox" | "button";
}) {
  return (
    <ol className="ssh-verification-steps">
      <li>
        Open this VPS on your hosting provider’s website, launch its browser
        console, and sign in to the VPS.
      </li>
      <li>
        Run this command in that console to list the server’s public SSH
        fingerprints:
        <div className="ssh-verification-command">
          <code>{command}</code>
          <CopyButton value={command} label="Copy verification command" />
        </div>
      </li>
      <li>
        Find the <code>SHA256:…</code> value that matches the fingerprint above
        exactly.{" "}
        {confirmation === "button"
          ? "Then select Fingerprint matches below."
          : "Then check the verification box below."}{" "}
        If none match, stop and check with your provider.
      </li>
    </ol>
  );
}
