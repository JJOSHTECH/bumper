# Environment Variables

Bumper has a number of environment variables to help with custom deployments and configuration. These should be set prior to executing Bumper.

| Setting            | Value                              | Description |
| ------------------ | ---------------------------------- | --------------------------------------------------------------------- |
| BUMPER_LISTEN      | {ipv4 address}                     | IP address to start server listeners on (default: 0.0.0.0) |
| BUMPER_ANNOUNCE_IP | {ipv4 address}                     | IP address announced to bots. Defaults to host IP; set if LISTEN is 0.0.0.0. |
| BUMPER_MQTT_PORT   | {port}                              | Primary MQTT TLS port (default: 443) |
| BUMPER_MQTT_ALT_PORT | {port}                            | Additional MQTT TLS port for compatibility (default: 8883) |
| BUMPER_CONF_PORT   | {port}                              | Web server port (default: 8007) |
| BUMPER_XMPP_PORT   | {port}                              | XMPP server port (default: 5223) |
| BUMPER_CA          | {full path to ca.crt location}     | The public CA certificate (ca.crt) to be loaded |
| BUMPER_CERT        | {full path to bumper.crt location} | The public server certificate (bumper.crt) to be used by the Bumper server |
| BUMPER_KEY         | {full path to bumper.key location} | The private server key (bumper.key) to be used by the Bumper server |
| BUMPER_LOGS        | {full path to logs directory}      | The directory where logs should be stored |
| BUMPER_DATA        | {full path to data directory}      | The directory where persistent data should be stored (bumper.db) |
| BUMPER_DEBUG       | true                               | Run Bumper with debug mode/logging |
| LOG_TO_STDOUT      | true                               | Instead of logging to logs/, logs to STDOUT |

