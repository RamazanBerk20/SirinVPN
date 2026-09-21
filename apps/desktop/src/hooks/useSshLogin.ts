import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { validateHost } from "../format";
import { errorMessage } from "../lib/errors";
import type { SavedSshLogin, SshCredentials } from "../types";

export function useSshLogin(host: string, active = true) {
  const destination = host.trim();
  const context = `${active}:${destination}`;
  const current = useRef(context);
  current.current = context;
  const generation = useRef(0);
  const [loadedFor, setLoadedFor] = useState("");
  const [checkingFor, setCheckingFor] = useState("");
  const [saved, setSaved] = useState<SavedSshLogin | null>(null);
  const [useSaved, setUseSaved] = useState(true);
  const [username, setUsername] = useState("root");
  const [port, setPort] = useState("22");
  const [auth, setAuth] =
    useState<SavedSshLogin["authentication"]>("password");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [sudoPassword, setSudoPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [forgetting, setForgetting] = useState(false);
  const clearSecrets = () => {
    setPassword("");
    setKeyPassphrase("");
    setSudoPassword("");
  };

  useEffect(() => {
    const epoch = ++generation.current;
    const validContext = () =>
      current.current === context && generation.current === epoch;
    clearSecrets();
    setSaved(null);
    setUseSaved(true);
    setError(null);
    setRemember(true);
    setUsername("root");
    setPort("22");
    setAuth("password");
    setKeyPath("");
    setLoadedFor("");
    setCheckingFor("");
    setForgetting(false);
    if (!active || !validateHost(destination)) return;
    // Avoid asking the wallet about each partial hostname while typing.
    let progressTimer: number | undefined;
    const timer = window.setTimeout(() => {
      // Fast wallet reads stay quiet. Announce only a lookup that remains slow
      // after the user has paused typing; credential validation still waits.
      progressTimer = window.setTimeout(() => {
        if (validContext()) setCheckingFor(context);
      }, 500);
      void api
        .getSshLogin(destination)
        .then((login) => {
          if (!validContext()) return;
          setSaved(login);
          if (login) {
            setUsername(login.username);
            setPort(String(login.ssh_port));
            setAuth(login.authentication);
            setKeyPath(login.private_key_path ?? "");
          }
        })
        .catch((reason) => {
          if (validContext())
            setError(
              errorMessage(
                reason,
                "The saved SSH login could not be read. You can enter a login below.",
              ),
            );
        })
        .finally(() => {
          window.clearTimeout(progressTimer);
          if (validContext()) setLoadedFor(context);
        });
    }, 250);
    return () => {
      window.clearTimeout(timer);
      window.clearTimeout(progressTimer);
      generation.current++;
    };
  }, [context]);

  const loading = active && validateHost(destination) && loadedFor !== context;
  const usingSaved = loadedFor === context && saved !== null && useSaved;
  const parsedPort = Number(port);
  const valid =
    active &&
    !loading &&
    !forgetting &&
    validateHost(destination) &&
    username.trim().length > 0 &&
    Number.isInteger(parsedPort) &&
    parsedPort > 0 &&
    parsedPort <= 65_535 &&
    (usingSaved ||
      auth === "agent" ||
      (auth === "password" && password.length > 0) ||
      (auth === "private_key" && keyPath.trim().length > 0));

  const prepare = async (fingerprint: string): Promise<SshCredentials> => {
    const epoch = generation.current;
    const ensureCurrent = () => {
      if (
        !active ||
        current.current !== context ||
        generation.current !== epoch
      )
        throw new Error(
          "The SSH operation was cancelled because its destination changed.",
        );
    };
    ensureCurrent();
    if (!valid) throw new Error("Enter a valid SSH login.");
    const credentials: SshCredentials = {
      username: username.trim(),
      ssh_port: parsedPort,
      authentication: auth,
      password: auth === "password" ? password : null,
      private_key_path: auth === "private_key" ? keyPath.trim() : null,
      private_key_passphrase:
        auth === "private_key" && keyPassphrase ? keyPassphrase : null,
      sudo_password:
        username.trim() === "root" || !sudoPassword ? null : sudoPassword,
      host_key_sha256: fingerprint,
    };
    if (!usingSaved && remember) {
      const login = await api.saveSshLogin({
        host: destination,
        ...credentials,
      });
      ensureCurrent();
      setSaved(login);
      setUseSaved(true);
      clearSecrets();
    }
    ensureCurrent();
    if (usingSaved || remember)
      return {
        ...credentials,
        authentication: "saved",
        password: null,
        private_key_path: null,
        private_key_passphrase: null,
        sudo_password: null,
      };
    return credentials;
  };

  const forget = async () => {
    const epoch = generation.current;
    setForgetting(true);
    setError(null);
    try {
      await api.forgetSshLogin(destination);
      if (current.current !== context || generation.current !== epoch) return;
      setSaved(null);
      setUseSaved(false);
      clearSecrets();
    } catch (reason) {
      if (current.current === context && generation.current === epoch)
        setError(
          errorMessage(reason, "The saved SSH login could not be removed."),
        );
    } finally {
      if (current.current === context && generation.current === epoch)
        setForgetting(false);
    }
  };

  return {
    username,
    setUsername,
    port,
    setPort,
    auth,
    setAuth,
    password,
    setPassword,
    keyPath,
    setKeyPath,
    keyPassphrase,
    setKeyPassphrase,
    sudoPassword,
    setSudoPassword,
    remember,
    setRemember,
    saved: loadedFor === context ? saved : null,
    usingSaved,
    loading,
    checkingSavedLogin: loading && checkingFor === context,
    forgetting,
    error,
    valid,
    prepare,
    clearSecrets,
    forget,
    edit: () => {
      setUseSaved(false);
      setError(null);
      clearSecrets();
    },
    reuse: () => {
      if (!saved) return;
      setUsername(saved.username);
      setPort(String(saved.ssh_port));
      setAuth(saved.authentication);
      setKeyPath(saved.private_key_path ?? "");
      setUseSaved(true);
      setError(null);
      clearSecrets();
    },
  };
}
