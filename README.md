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

1\. Add [Whonix's Signing Key](https://www.whonix.org/wiki/Whonix_Signing_Key).

```
sudo apt-key --keyring /etc/apt/trusted.gpg.d/whonix.gpg adv --keyserver hkp://ipv4.pool.sks-keyservers.net:80 --recv-keys 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
```

3\. Add Whonix's APT repository.

```
echo "deb http://deb.whonix.org stretch main" | sudo tee /etc/apt/sources.list.d/whonix.list
```

4\. Update your package lists.

```
sudo apt-get update
```

5\. Install `onion-grater`.

```
sudo apt-get install onion-grater
```

## How to Build deb Package ##

Replace `apparmor-profile-torbrowser` with the actual name of this package with `onion-grater` and see [instructions](https://www.whonix.org/wiki/Dev/Build_Documentation/apparmor-profile-torbrowser).

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Professional Support](https://www.whonix.org/wiki/Professional_Support)

## Payments ##

`onion-grater` requires [payments](https://www.whonix.org/wiki/Payments) to stay alive!
