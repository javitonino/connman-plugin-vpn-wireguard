#define PLUGIN_NAME "wireguard"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <netdb.h>

#include <dbus/dbus.h>
#include <connman/plugin.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/vpn/plugins/vpn.h>

static char * cidr_to_netmask(const char * address) {
    char *cidr = index(address, '/');
    int prefix_len = 32;
    if (cidr) {
        prefix_len = atoi(cidr + 1);
    }
    struct in_addr mask;
    mask.s_addr = ntohl(((1<<prefix_len)-1)<<(32-prefix_len));
    return inet_ntoa(mask);
}

static char * resolve(const char *hostname) {
    struct addrinfo hints = {.ai_family = AF_INET}, *addrs;
    char *resolved;

    int err = getaddrinfo(hostname, NULL, &hints, &addrs);
    if (err != 0)
    {
        return NULL;
    }

    struct sockaddr_in *addr = (struct sockaddr_in*)addrs->ai_addr;
    if (addr) {
        resolved = inet_ntoa(addr->sin_addr);
    }

    freeaddrinfo(addrs);
    return resolved;
}

static void configure_routes(struct vpn_provider *provider) {
	char key[10];
	gchar **allowed_ips = g_strsplit(vpn_provider_get_string(provider, "WireGuard.Peer.AllowedIPs"), ",", 0);
	for(int i = 0; allowed_ips[i] != NULL; i++) {
		// Support "," and ", " as separators: skip the initial space
		gchar *cidr = allowed_ips[i];
		if (cidr[0] == ' ') cidr++;

		int ip = index(cidr, ':') ? 6 : 4;
		if (ip == 6) continue; // IPv6 not supported for now
		char *slash = index(cidr, '/');

		if (ip == 4) {
			// Netmask for IPv4
			char *mask = cidr_to_netmask(cidr);
			sprintf(key, "msk4%d", i);
			vpn_provider_append_route(provider, key, mask);

			sprintf(key, "via4%d", i);
			vpn_provider_append_route(provider, key, "0.0.0.0");
		} else {
			// Prefix length for IPv6
			sprintf(key, "msk6%d", i);
			vpn_provider_append_route(provider, key, slash + 1);

			sprintf(key, "via6%d", i);
			vpn_provider_append_route(provider, key, "::");
		}

		if (slash) *slash = 0;
		sprintf(key, "net%d%d", ip, i);
		vpn_provider_append_route(provider, key, cidr);
	}
	g_strfreev(allowed_ips);
}

static int wg_save(struct vpn_provider *provider, GKeyFile *keyfile) {
	const char* group = vpn_provider_get_save_group(provider);
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.PublicKey", vpn_provider_get_string(provider, "WireGuard.Peer.PublicKey"));
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.AllowedIPs", vpn_provider_get_string(provider, "WireGuard.Peer.AllowedIPs"));
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.PersistentKeepalive", vpn_provider_get_string(provider, "WireGuard.Peer.PersistentKeepalive"));
	g_key_file_set_string(keyfile, group, "WireGuard.Peer.PresharedKey", vpn_provider_get_string(provider, "WireGuard.Peer.PresharedKey"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.Address", vpn_provider_get_string(provider, "WireGuard.Interface.Address"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.PrivateKey", vpn_provider_get_string(provider, "WireGuard.Interface.PrivateKey"));
	g_key_file_set_string(keyfile, group, "WireGuard.Interface.DNS", vpn_provider_get_string(provider, "WireGuard.Interface.DNS"));

	return 0;
}

static void wg_died(struct connman_task *task, int exit_code, void *provider) {
	vpn_died(task, exit_code, provider);
}

static int wg_notify(DBusMessage *msg, struct vpn_provider *provider) {
	struct connman_ipaddress *ipaddress = connman_ipaddress_alloc(AF_INET);
	const char *address = vpn_provider_get_string(provider, "WireGuard.Interface.Address");
	const char *host = vpn_provider_get_string(provider, "Host");
	char *gateway = strdup(host);
	char *portsep = strchr(gateway, ':');
	if (portsep) *portsep = 0;
	char *gw_address = strdup(resolve(gateway));

	connman_ipaddress_set_ipv4(ipaddress, (char *)address, cidr_to_netmask(address), gw_address);
	connman_ipaddress_set_p2p(ipaddress, true);
	vpn_provider_set_ipaddress(provider, ipaddress);

	connman_ipaddress_free(ipaddress);
	free(gateway);
	free(gw_address);


	configure_routes(provider);

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
	connman_task_add_variable(task, "WG_PEER_PRESHARED_KEY", vpn_provider_get_string(provider, "WireGuard.Peer.PresharedKey"));
	connman_task_add_variable(task, "WG_INTERFACE_ADDRESS", vpn_provider_get_string(provider, "WireGuard.Interface.Address"));
	connman_task_add_variable(task, "WG_INTERFACE_PRIVATE_KEY", vpn_provider_get_string(provider, "WireGuard.Interface.PrivateKey"));

	int fd = fileno(stderr);
	err = connman_task_run(task, wg_died, provider, NULL, &fd, &fd);
	if (!err) {
		cb(provider, user_data, 0);
	}
	return err;
}

static int wg_route_env_parse(struct vpn_provider *provider, const char *key, int *family, unsigned long *idx, enum vpn_provider_route_type *type) {
	if (g_str_has_prefix(key, "net")) {
		*type = VPN_PROVIDER_ROUTE_TYPE_ADDR;
	} else if (g_str_has_prefix(key, "msk")) {
		*type = VPN_PROVIDER_ROUTE_TYPE_MASK;
	} else if (g_str_has_prefix(key, "via")) {
		*type = VPN_PROVIDER_ROUTE_TYPE_GW;
	} else
		return -EINVAL;

	*family = key[3] == '4' ? AF_INET : AF_INET6;
	*idx = g_ascii_strtoull(key + 4, NULL, 10);

	return 0;
}

static struct vpn_driver vpn_driver = {
	.connect = wg_connect,
	.save = wg_save,
	.notify = wg_notify,
	.route_env_parse = wg_route_env_parse,
};

static int wg_init(void) {
	return vpn_register(PLUGIN_NAME, &vpn_driver, SCRIPTDIR "/wireguard.sh");

}

static void wg_exit(void) {
	vpn_unregister(PLUGIN_NAME);
}

CONNMAN_PLUGIN_DEFINE(wireguard, "Wireguard VPN plugin", CONNMAN_VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT, wg_init, wg_exit);
