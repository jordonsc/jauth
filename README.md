jAuth
=====
Jordon's cheeky quick-connect for the OB VPN.

* Runs a `vpn up`
* Enters your credentials
* Calculates your Google Authenticator hash

Requirements
------------
* Python 3 (must be callable via `python3`)
* `sbt-vpn` repo (must be callable via `/sbin/vpn` with default options)
* `expect` installed (`apt install expect`)

Usage
-----
You need your OB username, password and Google Authenticator hash in three files locked down to
only root read access. 

    /var/local/ob/usr
    /var/local/ob/pw
    /var/local/ob/ga

Each file should be in plain text and not contain any new-line characters.

### Google Authenticator Hash
The GA hash is provided under the QR code when your first authenticate with the OB VPN portal. If you
have already authenticated, you will need to clear your GA token (via IT) and login again.


### Connecting
Once your three auth files are populated, run

    ./vpn-up.sh

Consider: `ln -s /path/to/vpn.sh /sbin/vpn-up`
