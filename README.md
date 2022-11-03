# WireGuard VPN plugin for Sailfish OS

This is a VPN plugin for connman. In contrary to the [upstream one](https://git.kernel.org/pub/scm/network/connman/connman.git/tree/vpn/plugins/wireguard.c?h=1.41&id=4a27c58ad8b1afd980ebe122ca178c7f659c025e), this one
uses the userspace implementation, so there's no need for the kernel module.

This can be configured from the settings UI with [this plugin](https://github.com/javitonino/jolla-settings-networking-plugin-vpn-wireguard).
