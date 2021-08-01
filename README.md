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

This package is produced independently of, and carries no guarantee from,
The Tor Project.
## How to install `onion-grater` using apt-get ##

1\. Download Whonix's Signing Key.

```
wget https://www.whonix.org/patrick.asc
```

Users can [check Whonix Signing Key](https://www.whonix.org/wiki/Whonix_Signing_Key) for better security.

2\. Add Whonix's signing key.

```
sudo apt-key --keyring /etc/apt/trusted.gpg.d/derivative.gpg add ~/patrick.asc
```

3\. Add Whonix's APT repository.

```
echo "deb https://deb.whonix.org bullseye main contrib non-free" | sudo tee /etc/apt/sources.list.d/derivative.list
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

See instructions. (Replace `generic-package` with the actual name of this package `onion-grater`.)

* **A)** [easy](https://www.whonix.org/wiki/Dev/Build_Documentation/generic-package/easy), _OR_
* **B)** [including verifying software signatures](https://www.whonix.org/wiki/Dev/Build_Documentation/generic-package)

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Professional Support](https://www.whonix.org/wiki/Professional_Support)

## Donate ##

`onion-grater` requires [donations](https://www.whonix.org/wiki/Donate) to stay alive!
