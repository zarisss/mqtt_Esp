#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/logging/log.h>
#include <string.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

#define WIFI_SSID "ACTFIBERNET"
#define WIFI_PASS "act12345"
#define MQTT_SUB_TOPIC "zephyr/test"
#define MQTT_PUB_TOPIC "zephyr/test"
#define MQTT_PAYLOAD "Hello from ESP32-Zephyr!"

// MQTT credentials
static const char mqtt_user[] = "admin";
static const char mqtt_pass[] = "sharish87";

static struct mqtt_utf8 client_user = {
    .utf8 = (uint8_t *)mqtt_user,
    .size = sizeof(mqtt_user) - 1
};
static struct mqtt_utf8 client_pass = {
    .utf8 = (uint8_t *)mqtt_pass,
    .size = sizeof(mqtt_pass) - 1
};
static uint8_t rx_buffer[256];
static uint8_t tx_buffer[256];

static struct mqtt_client client;
static struct sockaddr_in broker;

static struct net_mgmt_event_callback wifi_cb;
static struct net_if *wifi_iface = NULL;
#define MQTT_BROKER_PORT 1883
#define MQTT_SUB_TOPIC "zephyr/test"
#define MQTT_PUB_TOPIC "zephyr/test"
#define MQTT_PAYLOAD "Hello from ESP32-Zephyr!"
void assign_static_ip(void)
{
    struct net_if *iface = net_if_get_default();
    struct in_addr addr, netmask, gw;

    net_addr_pton(AF_INET, "192.168.0.200", &addr);
    net_addr_pton(AF_INET, "255.255.255.0", &netmask);
    net_addr_pton(AF_INET, "192.168.0.1", &gw);

    net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);
    net_if_ipv4_set_netmask(iface, &netmask);
    net_if_ipv4_set_gw(iface, &gw);

    net_if_up(iface);  // Ensure interface is marked as UP
}

static void mqtt_event_handler(struct mqtt_client *const c, const struct mqtt_evt *evt) {
    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        LOG_INF("✅ MQTT connected");

        struct mqtt_topic sub_topic = {
            .topic = {
                .utf8 = MQTT_SUB_TOPIC,
                .size = strlen(MQTT_SUB_TOPIC)
            },
            .qos = MQTT_QOS_1_AT_LEAST_ONCE
        };

        struct mqtt_subscription_list sub_list = {
            .list = &sub_topic,
            .list_count = 1,
            .message_id = 1
        };

        mqtt_subscribe(c, &sub_list);
        LOG_INF("📡 Subscribed to topic: %s", MQTT_SUB_TOPIC);

        struct mqtt_publish_param pub_param = {
            .message.topic = {
                .topic = {
                    .utf8 = MQTT_PUB_TOPIC,
                    .size = strlen(MQTT_PUB_TOPIC)
                },
                .qos = MQTT_QOS_1_AT_LEAST_ONCE
            },
            .message.payload.data = MQTT_PAYLOAD,
            .message.payload.len = strlen(MQTT_PAYLOAD),
            .message_id = 2,
            .dup_flag = 0,
            .retain_flag = 0
        };

        mqtt_publish(c, &pub_param);
        LOG_INF("📨 Published message to topic: %s", MQTT_PUB_TOPIC);
        break;

    case MQTT_EVT_PUBLISH: {
        const struct mqtt_publish_param *p = &evt->param.publish;
        if (p->message.payload.data) {
            LOG_INF("📥 Received: %.*s", p->message.payload.len, (char *)p->message.payload.data);
        } else {
            LOG_ERR("⚠️ MQTT payload data was NULL");
        }
        break;
    }

    case MQTT_EVT_DISCONNECT:
        LOG_ERR("❌ MQTT disconnected");
        break;

    default:
        break;
    }
}


static void wifi_event_handler(struct net_mgmt_event_callback *cb,
                               uint32_t mgmt_event, struct net_if *iface)
{
    if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
        LOG_INF("✅ Connected to Wi-Fi");
    } else if (mgmt_event == NET_EVENT_WIFI_DISCONNECT_RESULT) {
        LOG_INF("❌ Disconnected from Wi-Fi");
    }
}

static int wifi_connect(void)
{
    struct wifi_connect_req_params params = {
        .ssid = WIFI_SSID,
        .ssid_length = strlen(WIFI_SSID),
        .psk = WIFI_PASS,
        .psk_length = strlen(WIFI_PASS),
        .channel = WIFI_CHANNEL_ANY,
        .security = WIFI_SECURITY_TYPE_PSK,
        .band = WIFI_FREQ_BAND_2_4_GHZ
    };

    wifi_iface = net_if_get_wifi_sta();
    if (!wifi_iface) {
        LOG_ERR("❌ Wi-Fi interface not found");
        return -ENODEV;
    }

    LOG_INF("🔌 Connecting to Wi-Fi: %s", WIFI_SSID);
    int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, wifi_iface, &params, sizeof(params));

    if (ret == 0) {
        net_if_up(wifi_iface);  // Ensure the interface is marked up
    }

    return ret;
}

static void print_ip_address(void)
{
    struct net_if *iface = net_if_get_default();
    char addr_str[NET_IPV4_ADDR_LEN];

    if (iface && iface->config.ip.ipv4) {
        struct net_if_addr *unicast = &iface->config.ip.ipv4->unicast[0];

        if (unicast->is_used) {
            net_addr_ntop(AF_INET, &unicast->address.in_addr, addr_str, sizeof(addr_str));
            LOG_INF("📡 Assigned Static IP: %s", addr_str);
        } else {
            LOG_ERR("❌ No IPv4 address assigned");
        }
    } else {
        LOG_ERR("❌ No IPv4 address configuration found");
    }
}

void main(void)
{
    LOG_INF("🚀 ESP32 Zephyr MQTT Start");

    net_mgmt_init_event_callback(&wifi_cb, wifi_event_handler,
        NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT);
    net_mgmt_add_event_callback(&wifi_cb);

    k_sleep(K_SECONDS(2));  // Let Wi-Fi subsystem initialize

    if (wifi_connect() != 0) {
        LOG_ERR("❌ Wi-Fi Connection Failed");
        return;
    }

    k_sleep(K_SECONDS(5));  // Wait for IP address
    assign_static_ip();     // ✅ Manually assign static IP
    k_sleep(K_SECONDS(1));
    print_ip_address();

    // Configure MQTT broker
    memset(&broker, 0, sizeof(broker));
    broker.sin_family = AF_INET;
    broker.sin_port = htons(1883);
    net_addr_pton(AF_INET, "192.168.0.107", &broker.sin_addr);

    mqtt_client_init(&client);
    client.broker = &broker;
    client.evt_cb = mqtt_event_handler;
    client.client_id.utf8 = (uint8_t *)"zephyr_esp32";
    client.client_id.size = strlen("zephyr_esp32");
    client.user_name = &client_user;
    client.password  = &client_pass;
    client.protocol_version = MQTT_VERSION_3_1_1;

    client.rx_buf = rx_buffer;
    client.rx_buf_size = sizeof(rx_buffer);
    client.tx_buf = tx_buffer;
    client.tx_buf_size = sizeof(tx_buffer);
    static int mqtt_sock_fd;

    mqtt_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mqtt_sock_fd < 0) {
        LOG_ERR("❌ Failed to create MQTT socket: %d", errno);
        return;
    }
    client.transport.type = MQTT_TRANSPORT_NON_SECURE;
    client.transport.tcp.sock = mqtt_sock_fd;         // ✅ Assign socket to transport
    //k_sleep(K_SECONDS(2));
    int rc = mqtt_connect(&client);
    if (rc) {
        LOG_ERR("❌ MQTT connect failed: %d", rc);
        return;
    }

    LOG_INF("📡 MQTT loop starting");

    while (1) {
        mqtt_input(&client);
        mqtt_live(&client);
        k_sleep(K_MSEC(500));
    }
}
