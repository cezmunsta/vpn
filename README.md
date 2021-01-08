# VPN Helper

```sh
usage: connect.py [-h] --config CONFIG [--duo] [--gpg] [--gpg-source GPG_SOURCE] [--dry-run] [CREDENTIALS]

Connect to OpenVPN

optional arguments:
  -h, --help            show this help message and exit

main options:
  CREDENTIALS           Specify the user for the connection [None]
  --config CONFIG       Specify the config to use
  --duo                 Require DUO authentication [True]
  --gpg                 Use GPG for credentials [True]
  --gpg-source GPG_SOURCE
                        GPG-encrypted source [./credentials.yaml.asc]

extra options:
  --dry-run, --simulate
                        Run through the motions, but take no action
```

## Encrypted credentials

GPG will read the credentials from the `GPG_SOURCE` file, the plaintext of which should in
the following format:

```yaml
---
<marker>:
  user: <username>
  pass: <password>
...
```

Multiple marker entries can be used in the same file as the code will lookup the one that
was requested for use. For example:

```yaml
---
demo:
  user: dummy
  pass: dummy
anotherdemo:
  user: dummy
  pass: dummy
...
```

## Example

The `GPG_SOURCE` is in the home directory and named `credentials.yaml.asc`.

```sh
$ openvpn/connect.py --config ${HOME}/certs/client.ovpn --gpg-source ${HOME}/credentials.yaml.asc demo
/usr/bin/gpg --status-fd 2 --no-tty --no-verbose --fixed-list-mode --batch --with-colons --use-agent --version
/usr/bin/gpg --status-fd 2 --no-tty --no-verbose --fixed-list-mode --batch --with-colons --use-agent --decrypt
[GNUPG:] ENC_TO F4F7A6A1A2C4DE67 1 0
[GNUPG:] KEY_CONSIDERED XXXA946226614B4 0
[GNUPG:] KEY_CONSIDERED XXXA946226614B4 0
[GNUPG:] DECRYPTION_KEY XXXF4F7A6A1A2C4DE67 XXXA946226614B4 u
[GNUPG:] ENC_TO DB7034CFD85E87FA 1 0
[GNUPG:] KEY_CONSIDERED XXXC7E8463C7418C0BE5 0
gpg: encrypted with 4096-bit RSA key, ID XXX, created 2016-08-14
      "demo <example.com>"
[GNUPG:] BEGIN_DECRYPTION
[GNUPG:] DECRYPTION_COMPLIANCE_MODE 23
[GNUPG:] DECRYPTION_INFO 2 9
[GNUPG:] PLAINTEXT 62 1525185349 credentials.yaml
[GNUPG:] PLAINTEXT_LENGTH 70
[GNUPG:] DECRYPTION_OKAY
[GNUPG:] GOODMDC
[GNUPG:] END_DECRYPTION
```
