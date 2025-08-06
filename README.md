# Whitelisting filter for dangerous Tor control protocol commands #

Filters out Tor control protocol commands that are dangerous for anonymity
such as GETINFO ADDRESS using a whitelist. Acts as a proxy between the client
application and Tor.

For example it allows using Tor Browser's New Identity feature on Anonymity
Distribution Workstations, fixes Tor Browser's about:tor default homepage and
Tor Button status indicator without exposing commands that are dangerous for
anonymity.

This package is supposed to be installed on Anonymity Distributions.

It seamlessly integrates if the anon-ws-disable-stacked-tor package
is installed on a Anonymity Distribution Workstations. For example it then
allows running a unmodified Tor Browser Bundle from The Tor Project without
Tor over Tor and with functional New Identity and about:tor.

This control port filter is written in Python. The original Python code
was forked from the Tails version of control port filter.

Source Code Contributions / Patches / Pull Requests:
Please discuss before doing significant development work.
This is a fork of Tails' onion-grater.
Therefore, you'll most likely will be asked to submit patches to upstream,
Tails first.

This package is produced independently of, and carries no guarantee from,
The Tor Project.

## How to install `onion-grater` using apt-get ##

1\. Download the APT Signing Key.

```
wget https://www.whonix.org/keys/derivative.asc
```

Users can [check the Signing Key](https://www.whonix.org/wiki/Signing_Key) for better security.

2\. Add the APT Signing Key.

```
sudo cp ~/derivative.asc /usr/share/keyrings/derivative.asc
```

3\. Add the derivative repository.

```
echo "deb [signed-by=/usr/share/keyrings/derivative.asc] https://deb.whonix.org trixie main contrib non-free" | sudo tee /etc/apt/sources.list.d/derivative.list
```

4\. Update your package lists.

```
sudo apt-get update
```

5\. Install `onion-grater`.

```
sudo apt-get install onion-grater
```

## How to Build deb Package from Source Code ##

Can be build using standard Debian package build tools such as:

```
dpkg-buildpackage -b
```

See instructions.

NOTE: Replace `generic-package` with the actual name of this package `onion-grater`.

* **A)** [easy](https://www.whonix.org/wiki/Dev/Build_Documentation/generic-package/easy), _OR_
* **B)** [including verifying software signatures](https://www.whonix.org/wiki/Dev/Build_Documentation/generic-package)

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Premium Support](https://www.whonix.org/wiki/Premium_Support)

## Donate ##

`onion-grater` requires [donations](https://www.whonix.org/wiki/Donate) to stay alive!
