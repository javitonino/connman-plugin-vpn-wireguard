#define PLUGIN_NAME "wireguard"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <net/if.h>

#include <dbus/dbus.h>
#include <connman/plugin.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/vpn/plugins/vpn.h>

char * cidr_to_netmask(char* address) {
    char *cidr = index(address, '/') + 1;
    int prefix_len = 24;
    if (cidr) {
        prefix_len = atoi(cidr);
    }
    struct in_addr mask;
    mask.s_addr = ntohl(((1<<prefix_len)-1)<<(32-prefix_len));
    return inet_ntoa(mask);
}

static int wg_save(struct vpn_provider *provider, GKeyFile *keyfile) {
	const char* group = vpn_provider_get_save_group(provider);
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.PublicKey", vpn_provider_get_string(provider, "WireGuard.Peer.PublicKey"));
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.AllowedIPs", vpn_provider_get_string(provider, "WireGuard.Peer.AllowedIPs"));
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.PersistentKeepalive", vpn_provider_get_string(provider, "WireGuard.Peer.PersistentKeepalive"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.Address", vpn_provider_get_string(provider, "WireGuard.Interface.Address"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.PrivateKey", vpn_provider_get_string(provider, "WireGuard.Interface.PrivateKey"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.DNS", vpn_provider_get_string(provider, "WireGuard.Interface.DNS"));

	return 0;
}

static void wg_died(struct connman_task *task, int exit_code, void *provider) {
	vpn_died(task, exit_code, provider);
}

static int wg_notify(DBusMessage *msg, struct vpn_provider *provider) {
	vpn_provider_set_boolean(provider, "SplitRouting", true, false);

	struct connman_ipaddress *ipaddress = connman_ipaddress_alloc(AF_INET);
	char *address = vpn_provider_get_string(provider, "WireGuard.Interface.Address");
	connman_ipaddress_set_ipv4(ipaddress, address, cidr_to_netmask(address), vpn_provider_get_string(provider, "Host"));
	vpn_provider_set_ipaddress(provider, ipaddress);
	connman_ipaddress_free(ipaddress);

	const char *nameservers = vpn_provider_get_string(provider, "WireGuard.Interface.DNS");
	if (nameservers)
		vpn_provider_set_nameservers(provider, nameservers);

	return VPN_PROVIDER_STATE_READY;
}

static int wg_connect(struct vpn_provider *provider, struct connman_task *task, const char *if_name, vpn_provider_connect_cb_t cb, const char *dbus_sender, void *user_data) {
	int err = 0;

	connman_task_add_variable(task, "WG_TUN", if_name);
	connman_task_add_variable(task, "WG_PEER_ENDPOINT", vpn_provider_get_string(provider, "Host"));
	connman_task_add_variable(task, "WG_PEER_PUBLIC_KEY", vpn_provider_get_string(provider, "WireGuard.Peer.PublicKey"));
	connman_task_add_variable(task, "WG_PEER_ALLOWED_IPS", vpn_provider_get_string(provider, "WireGuard.Peer.AllowedIPs"));
	connman_task_add_variable(task, "WG_PEER_PERSISTENT_KEEPALIVE", vpn_provider_get_string(provider, "WireGuard.Peer.PersistentKeepalive"));
	connman_task_add_variable(task, "WG_INTERFACE_ADDRESS", vpn_provider_get_string(provider, "WireGuard.Interface.Address"));
	connman_task_add_variable(task, "WG_INTERFACE_PRIVATE_KEY", vpn_provider_get_string(provider, "WireGuard.Interface.PrivateKey"));

	int fd = fileno(stderr);
	err = connman_task_run(task, wg_died, provider, NULL, &fd, &fd);
	if (!err) {
		cb(provider, user_data, 0);
	}
	return err;
}

static struct vpn_driver vpn_driver = {
	.connect = wg_connect,
	.save = wg_save,
	.notify = wg_notify
};

static int wg_init(void) {
	return vpn_register(PLUGIN_NAME, &vpn_driver, SCRIPTDIR "/wireguard.sh");

}

static void wg_exit(void) {
	vpn_unregister(PLUGIN_NAME);
}

CONNMAN_PLUGIN_DEFINE(wireguard, "Wireguard VPN plugin", CONNMAN_VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT, wg_init, wg_exit);
