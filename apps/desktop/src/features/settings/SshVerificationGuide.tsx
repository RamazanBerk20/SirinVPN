import { CopyButton } from "../../components/CopyButton";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { Fragment } from "react";

const command =
  'for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -l -E sha256 -f "$key"; done';

export function SshVerificationGuide({
  confirmation = "checkbox",
}: {
  confirmation?: "checkbox" | "button";
}) {
  return (
    <ol className="ssh-verification-steps">
      <li>{t("ssh.guide.openConsole")}</li>
      <li>
        {t("ssh.guide.runCommand")}
        <div className="ssh-verification-command">
          {/* Each token stays whole (hyphens included), so a retyped command keeps "-E" and "sha256" intact. */}
          <code>{command.split(" ").map((word, index) => <Fragment key={index}>{index > 0 && " "}<span>{word}</span></Fragment>)}</code>
          <CopyButton value={command} label={t("ssh.guide.copyCommand")} />
        </div>
      </li>
      <li>
        <Rich
          id={confirmation === "button" ? "ssh.guide.matchButton" : "ssh.guide.matchCheckbox"}
          tags={{ code: (content) => <code>{content}</code> }}
        />
      </li>
    </ol>
  );
}
