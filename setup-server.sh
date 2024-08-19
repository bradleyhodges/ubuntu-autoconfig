#!/bin/bash

# Echo commands to the console
set -x

# This script is designed to be run on a new DigitalOcean droplet, designated as an API server, to
# configure it with FrankenPHP (Caddy server), PHP, Sentry, Cloudflare Tunnel, and other utilities
# in a secure way.

# FrankenPHP is essentially a version of the Caddy web server that is bundled with additional 
# functionality specifically tailored for running PHP applications efficiently. It combines 
# the Caddy server with a PHP runtime and integrates features like worker mode for PHP and 
# built-in support for popular PHP extensions.

# You can make this script executable by running:
#   > chmod +x ./setup-server.sh
# And then run it with:
#   > sudo ./setup-server.sh
# or, if you're feeling fancy, all at once:
#   > chmod +x ./setup-server.sh && sudo ./setup-server.sh

# *********************************************************** #
# *     Configuration parameters - please set these now     * #
# *********************************************************** #
# Things you definitely need to check and change if necessary:
SERVER_EMAIL="sysadmin@wases.com.au" 
CF_API_TOKEN="" # Replace with your Cloudflare API token with DNS, Tunnel, and Certificate permissions
CF_ACCOUNT_ID="26801e6068adefb82b51e4c3fe327105" # Replace with your Cloudflare Account ID
CF_ZONE_ID="79df1b429fbc516754f7cf9d297fdcbf" # Replace with your Cloudflare website's Zone ID
SENTRY_DSN="" # Replace with your Sentry DSN 
SERVER_FQDN=" # Replace with your server's public hostname (FQDN) - eg. api.vitalis.wases.com.au"
DOCUMENT_ROOT_PATH="/var/www" # This is where your files will live :)

# Things you probably don't need to change, but you can if you want to:
PUBLIC_ROOT_PATH="$DOCUMENT_ROOT_PATH/public" # This is where your public files will live
UTILITIES_PATH="$DOCUMENT_ROOT_PATH/utilities" # This is where your utilities will live
COMPOSER_PATH="$DOCUMENT_ROOT_PATH/composer" # This is where Composer will be installed
COMPOSER_AUTOLOAD_PATH="$COMPOSER_PATH/vendor/autoload.php" # This is where Composer autoload will be generated
GO_VERSION="latest"  # specify a specific Go version (e.g., "1.20.3") if you want, otherwise we'll get the latest version automatically
# *********************************************************** #

# ` > start droplet configuration script
# `
# `
# ` !! DO NOT CHANGE ANYTHING AFTER THIS POINT. THERE IS NO NEED TO MODIFY THE SCRIPT BEYOND THIS LINE. !!
# `
# `
# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Get the configuration script ready. Set up logging, etc.  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Ensure script is run as root or with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or use sudo."
    exit 1
fi

# Get the server's hostname
SERVER_HOSTNAME=$(hostname)

# Redirect output to both console and log file
exec > >(tee -a /root/.initialisation-script.log) 2>&1 

set -e # Exit script on error

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Check for Required Configuration Variables  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    if [ -z "$SERVER_EMAIL" ]; then
        echo "Error: Server Email Address is not set. Exiting."
        exit 1
    fi

    if [ -z "$CF_API_TOKEN" ]; then
        echo "Error: Cloudflare API token is not set. Exiting."
        exit 1
    fi

    if [ -z "$CF_ACCOUNT_ID" ]; then
        echo "Error: Cloudflare Account ID is not set. Exiting."
        exit 1
    fi

    if [ -z "$CF_ZONE_ID" ]; then
        echo "Error: Cloudflare Zone ID is not set. Exiting."
        exit 1
    fi

    if [ -z "$SENTRY_DSN" ]; then
        echo "Error: Sentry DSN is not set. Exiting."
        exit 1
    fi

    if [ -z "$SERVER_FQDN" ]; then
        echo "Error: Server FQDN is not set. Exiting."
        exit 1
    fi

    if [ -z "$DOCUMENT_ROOT_PATH" ]; then
        echo "Error: Server Document Root is not set. Exiting."
        exit 1
    fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Architecture Check: Ensure the OS architecture is x86_64  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    ARCH=$(uname -m)
    if [ "$ARCH" != "x86_64" ]; then 
        echo "Error: This script only supports x86_64 architecture." 
        exit 1 
    fi 

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Update existing packages and get new dependencies  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Update and upgrade all packages
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update || { echo "Package update/upgrade failed"; exit 1; }
    sudo apt-get install -y software-properties-common  || { echo "Package update/upgrade failed"; exit 1; }
    sudo add-apt-repository -y ppa:ondrej/php || true
    sudo apt-get update && sudo apt-get upgrade -y || { echo "Package update/upgrade failed"; exit 1; }

    # Install necessary dependencies if not already installed
    dependencies=(curl ufw unzip cron git libssl-dev zlib1g-dev pkg-config openssl)
    for pkg in "${dependencies[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        sudo apt-get install -y "$pkg" || { echo "Failed to install $pkg"; exit 1; }
    else
        echo "$pkg is already installed, skipping."
    fi
    done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up a non-privileged user for FrankenPHP (Caddy) to use  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Create directories if they don't already exist
    directories=($DOCUMENT_ROOT_PATH $PUBLIC_ROOT_PATH $UTILITIES_PATH $COMPOSER_PATH /etc/caddy /var/lib/caddy /var/log/caddy)
    for dir in "${directories[@]}"; do
        [ ! -d "$dir" ] && mkdir -p "$dir"
    done

    # Create a dedicated non-privileged user for Caddy if it doesn't exist
    if ! id "caddyuser" &> /dev/null; then
        sudo useradd -r -d $DOCUMENT_ROOT_PATH -s /usr/sbin/nologin caddyuser || { echo "Failed to create caddyuser"; exit 1; }
        echo "Created user 'caddyuser'."
    else
        echo "User 'caddyuser' already exists, skipping."
    fi

    # Ensure the appropriate directories are owned by the Caddy user
    sudo chown -R caddyuser:caddyuser $DOCUMENT_ROOT_PATH /etc/caddy /var/lib/caddy /var/log/caddy

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up environment variables  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set up environment variables
    cat <<EOF > $DOCUMENT_ROOT_PATH/.env
DOCUMENT_ROOT_PATH=$DOCUMENT_ROOT_PATH
COMPOSER_AUTOLOAD_PATH=$COMPOSER_AUTOLOAD_PATH
UTILITIES_PATH=$UTILITIES_PATH
CF_ACCOUNT_ID=$CF_ACCOUNT_ID
CF_ZONE_ID=$CF_ZONE_ID
SERVER_FQDN=$SERVER_FQDN
EOF

    # Secure the .env file: make it readable only by the web server user
    chown caddyuser:caddyuser $DOCUMENT_ROOT_PATH/.env
    chmod 600 $DOCUMENT_ROOT_PATH/.env

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install the latest version of PHP ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Install PHP with PHP-FPM for usage with FrankenPHP instead of Apache
    echo "Installing PHP and PHP-FPM..."
    sudo apt-get install -y php-fpm php-cli php-common php-mysql php-curl php-xml php-zip php-dev php-embed

    php_version=$(php -v | head -n 1)
    echo "PHP successfully installed. Version: $php_version"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install FrankenPHP (Prebuilt Binary) ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Downloading FrankenPHP binary..."
    FRANKENPHP_BINARY_URL="https://github.com/dunglas/frankenphp/releases/latest/download/frankenphp-linux-x86_64"
    curl -L -o /usr/local/bin/frankenphp "$FRANKENPHP_BINARY_URL" || { echo "Failed to download FrankenPHP binary"; exit 1; }
    chmod +x /usr/local/bin/frankenphp

    # Verify FrankenPHP installation
    if ! command -v frankenphp &> /dev/null; then
        echo "FrankenPHP installation failed."
        exit 1
    fi
    echo "FrankenPHP successfully installed. Version: $(frankenphp version)"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Create the systemd service file for FrankenPHP ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    sudo tee /etc/systemd/system/frankenphp.service > /dev/null <<EOF
[Unit]
Description=FrankenPHP server
Documentation=https://frankenphp.org/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddyuser
Group=caddyuser
ExecStart=/usr/local/bin/frankenphp run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/frankenphp reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
ExecStop=/usr/local/bin/frankenphp stop
Restart=on-failure
RestartSec=10
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd to apply the new service file
    sudo systemctl daemon-reload

    # Enable and start the FrankenPHP service
    sudo systemctl enable frankenphp
    sudo systemctl start frankenphp || { echo "Failed to start FrankenPHP service"; exit 1; }

    # Verify if the service is running
    sudo systemctl is-active --quiet frankenphp && echo "FrankenPHP service is running." || { echo "FrankenPHP service failed to start"; exit 1; }

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install Composer  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set COMPOSER_ALLOW_SUPERUSER to suppress warnings when running as root
    export COMPOSER_ALLOW_SUPERUSER=1

    if ! command -v composer &> /dev/null; then
        echo "Installing Composer..."

        # Install Composer
        curl -s https://getcomposer.org/installer | php || { echo "Composer installation failed"; exit 1; }
        mv composer.phar /usr/local/bin/composer

        # Verify Composer installation
        if command -v composer &> /dev/null; then
            echo "Composer successfully installed. Version: $(composer --version)"
        else
            echo "Composer installation failed."
            exit 1
        fi
    else
        echo "Composer is already installed, skipping."
    fi

    # Update the PHP include_path to include the utilities directory
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$UTILITIES_PATH\"|" /etc/php/*/fpm/php.ini || true
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$UTILITIES_PATH\"|" /etc/php/*/cli/php.ini || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install SES PHP API Utilities  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set up the Composer configuration for the utilities
    COMPOSER_JSON_PATH="$UTILITIES_PATH/composer.json"
    CUSTOM_VENDOR_DIR="$COMPOSER_PATH/vendor"

    # Ensure Git trusts the utilities directory
    git config --global --add safe.directory "$UTILITIES_PATH"

    # Set COMPOSER_ALLOW_SUPERUSER to suppress warnings when running as root
    export COMPOSER_ALLOW_SUPERUSER=1

    # Make Composer use the custom vendor directory
    export COMPOSER_VENDOR_DIR="$CUSTOM_VENDOR_DIR"
    # export COMPOSER_HOME="$COMPOSER_PATH"

    # Make Composer ALWAYS use the custom home (even after this script is done running)
    echo 'export COMPOSER_VENDOR_DIR="$CUSTOM_VENDOR_DIR"' >> ~/.profile
    # echo 'export COMPOSER_HOME="$COMPOSER_PATH"' >> ~/.profile

    # Clone the SES PHP API Utilities repository if not already cloned
    if [ ! -d "$UTILITIES_PATH/.git" ]; then
        echo "Cloning SES PHP API Utilities from GitHub..."
        git clone https://github.com/dfes-ses/common-api-utilities.git "$UTILITIES_PATH" || { echo "Failed to clone SES API Utilities"; exit 1; }
    else
        echo "SES PHP API Utilities repository already cloned, pulling the latest changes..."
        cd "$UTILITIES_PATH" && git pull || { echo "Failed to update SES API Utilities"; exit 1; }
    fi

    # cd to the utilities directory
    cd "$UTILITIES_PATH"

    # Create composer.json if it doesn't exist
    if [ ! -f "$COMPOSER_JSON_PATH" ]; then
        echo "Creating composer.json with custom vendor directory..."
        cat <<EOF > "$COMPOSER_JSON_PATH"
{
    "config": {
        "vendor-dir": "$CUSTOM_VENDOR_DIR"
    },
    "require": {
        // Add any required packages if necessary
    }
}
EOF
    else
        echo "composer.json already exists. Ensuring custom vendor directory is set..."
        if ! grep -q '"vendor-dir":' "$COMPOSER_JSON_PATH"; then
            # Insert the vendor-dir configuration into the existing composer.json file
            sed -i '/"config": {/a \ \ \ \ "vendor-dir": "'"$CUSTOM_VENDOR_DIR"'",' "$COMPOSER_JSON_PATH"
        fi
    fi

    # Install dependencies in non-interactive mode
    if composer install --ignore-platform-reqs --no-dev -a --optimize-autoloader --no-interaction; then
        echo "Composer dependencies installed successfully."
    else
        echo "Failed to install Composer dependencies."
        exit 1
    fi

    # Install Sentry SDK for PHP as well
    composer require sentry/sentry --no-dev --optimize-autoloader --no-interaction || true;

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Configure PHP for Caddy  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Configure PHP to work with Caddy
    sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /etc/php/*/cli/php.ini
    sed -i 's/^;opcache.enable=1/opcache.enable=1/' /etc/php/*/cli/php.ini
    sed -i 's/^;opcache.memory_consumption=128/opcache.memory_consumption=256/' /etc/php/*/cli/php.ini
    sed -i 's/^;opcache.interned_strings_buffer=8/opcache.interned_strings_buffer=16/' /etc/php/*/cli/php.ini
    sed -i 's/^;opcache.max_accelerated_files=10000/opcache.max_accelerated_files=20000/' /etc/php/*/cli/php.ini
    sed -i 's/^;opcache.revalidate_freq=2/opcache.revalidate_freq=60/' /etc/php/*/cli/php.ini

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Generate SSL Certificate ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Generating SSL certificate..."
    SSL_CERT_PATH="/etc/caddy/ssl/certs/selfsigned.crt"
    SSL_KEY_PATH="/etc/caddy/ssl/private/selfsigned.key"

    # Create the directories
    sudo mkdir -p /etc/caddy/ssl/certs /etc/caddy/ssl/private

    # Create SSL certificate if it doesn't exist
    if [ ! -f "$SSL_CERT_PATH" ] || [ ! -f "$SSL_KEY_PATH" ]; then
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_KEY_PATH" \
            -out "$SSL_CERT_PATH" \
            -subj "/CN=$SERVER_FQDN"
        echo "Self-signed SSL certificate generated."
    else
        echo "SSL certificate already exists, skipping generation."
    fi

    # Set the correct permissions for the SSL certificate
    sudo chmod 600 "$SSL_KEY_PATH"
    sudo chmod 644 "$SSL_CERT_PATH"

    # Give the caddyuser access to the SSL certificate and key file
    sudo chown -R caddyuser:caddyuser "$SSL_KEY_PATH"
    sudo chown -R caddyuser:caddyuser "$SSL_CERT_PATH"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Configure Caddy for PHP with FrankenPHP  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    sudo mkdir -p /etc/caddy
    cat <<EOF > /etc/caddy/Caddyfile
{
    email $SERVER_EMAIL  # Set your email for Let's Encrypt notifications
    auto_https off  # Disable automatic HTTP-01 challenges
    frankenphp
    servers {
        protocols h1 h2 h3  # Enable HTTP/1, HTTP/2, and HTTP/3 (QUIC)
    }
}

:443 {
    root * $PUBLIC_ROOT_PATH
    php_server {  # This will enable the FrankenPHP integration
        # Add your PHP handling configuration here
    }

    # Enable gzip and Brotli compression
	encode zstd br gzip

    # Enable security headers
    header {
        Cache-Control max-age=86400, public
        Strict-Transport-Security max-age=31536000;
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        X-XSS-Protection "1; mode=block"
        Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self';"
        Referrer-Policy "no-referrer"
        Feature-Policy "geolocation 'none'; microphone 'none'; camera 'none'"
    }

    tls $SSL_CERT_PATH $SSL_KEY_PATH  # Add TLS with the self-signed certificate

    try_files {path} {path}/ /index.php?{query}

    @phpFiles {
        path *.php
    }
    handle @phpFiles {
        try_files {path} =404
    }
}
EOF

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Make Caddy use the non-privileged user  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set permissions for the document root
    chown -R caddyuser:caddyuser "$DOCUMENT_ROOT_PATH"
    chmod -R 755 "$DOCUMENT_ROOT_PATH"
    sudo chown -R caddyuser:caddyuser /etc/caddy

    # Restart FrankenPHP service (Caddy) to apply the new user and group
    sudo systemctl restart frankenphp

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install Cloudflare Argo Tunnel  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    if ! command -v cloudflared &> /dev/null; then
        curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb || { echo "Failed to download Cloudflare Argo Tunnel"; exit 1; }
        sudo dpkg -i cloudflared.deb || { echo "Failed to install Cloudflare Argo Tunnel"; exit 1; }
        rm cloudflared.deb
    else
        echo "Cloudflare Argo Tunnel is already installed, skipping."
    fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up the software firewall  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set up ufw firewall rules
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http  # Port 80
    ufw allow https  # Port 443
    ufw allow 7844/tcp  # Cloudflare Tunnel (HTTP2/QUIC) on TCP
    ufw allow 7844/udp  # Cloudflare Tunnel (HTTP2/QUIC) on UDP
    ufw --force enable

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Allow Cloudflare IPs through firewall  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Fetch Cloudflare IPs and allow them in ufw
    curl -sf https://www.cloudflare.com/ips-v4 -o /tmp/cloudflare-ips-v4.txt || { echo "Failed to fetch Cloudflare IPv4 list"; exit 1; }
    curl -sf https://www.cloudflare.com/ips-v6 -o /tmp/cloudflare-ips-v6.txt || { echo "Failed to fetch Cloudflare IPv6 list"; exit 1; }

    for ip in $(cat /tmp/cloudflare-ips-v4.txt); do
        ufw allow from $ip to any port 80,443,7844 proto tcp
    done

    for ip in $(cat /tmp/cloudflare-ips-v6.txt); do
        ufw allow from $ip to any port 80,443,7844 proto tcp
    done

    # Enable ufw firewall
    ufw reload

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Create a cron job to update Cloudflare IPs automatically and allow them in ufw ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    (crontab -l ; echo "0 11 * * TUE /usr/bin/curl -sf https://www.cloudflare.com/ips-v4 -o /tmp/cloudflare-ips-v4.txt && /usr/bin/curl -sf https://www.cloudflare.com/ips-v6 -o /tmp/cloudflare-ips-v6.txt && for ip in \\\$(cat /tmp/cloudflare-ips-v4.txt); do ufw allow from \\\$ip to any port 80,443,7844 proto tcp; done && for ip in \\\$(cat /tmp/cloudflare-ips-v6.txt); do ufw allow from \\\$ip to any port 80,443,7844 proto tcp; done || echo 'Failed to update Cloudflare IPs' >> /var/log/cloudflare-update.log") | crontab -

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Log rotation for Cloudflare update log ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "/var/log/cloudflare-update.log {
        rotate 7
        daily
        compress
        missingok
        notifempty
    }" > /etc/logrotate.d/cloudflare-update

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Configure performance parameters ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Optimize system-level performance (e.g., increase file descriptor limits)
    echo "fs.file-max = 100000" >> /etc/sysctl.conf
    sysctl -p

    # Optimize ulimit
    cat <<EOF > /etc/security/limits.conf
* soft nofile 100000
* hard nofile 100000
EOF

    # Adjust swappiness to reduce swapping
    echo "vm.swappiness = 10" >> /etc/sysctl.conf || true
    sysctl -p || true

    # Disabling Disable Transparent Huge Pages (THP) for better memory performance
    echo "never" > /sys/kernel/mm/transparent_hugepage/enabled || true
    echo "never" > /sys/kernel/mm/transparent_hugepage/defrag || true

    # Make THP changes persistent across reboots by adding it to /etc/rc.local
    cat <<EOF > /etc/rc.local
#!/bin/bash
if test -f /sys/kernel/mm/transparent_hugepage/enabled; then
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi
if test -f /sys/kernel/mm/transparent_hugepage/defrag; then
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
fi
exit 0
EOF
    chmod +x /etc/rc.local || true

    # Set the CPU governor to performance
    apt-get install -y cpufrequtils || true
    echo "GOVERNOR=performance" > /etc/default/cpufrequtils || true
    systemctl restart cpufrequtils || true

    # Increase TCP backlog queue size and enable TCP Fast Open and BBR
    echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf || true
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf || true
    echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf || true
    sysctl -p || true

    # Automatic daily cleanup script
    cat <<EOF > /etc/cron.daily/daily_cleanup
#!/bin/bash
# Clean up temporary files
find /tmp -type f -atime +7 -delete
find /var/tmp -type f -atime +7 -delete
# Rotate logs and clean up old logs
logrotate -f /etc/logrotate.conf
EOF

    # Make the cleanup script executable
    chmod +x /etc/cron.daily/daily_cleanup

    # Restart cron service to apply new cron jobs
    systemctl restart cron

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up a Sentry error handler import ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Sentry Configuration - Error reporting
    cat <<EOF > $DOCUMENT_ROOT_PATH/sentry.php
<?php
	\Sentry\init(['dsn' => '$SENTRY_DSN' ]);
	function handleError(\Throwable \$exception) {
	    \Sentry\captureException(\$exception);
	}
	set_exception_handler('handleError');
?>
EOF

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set final permissions  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    chmod 600 /etc/cron.daily/daily_cleanup
    chmod 600 $DOCUMENT_ROOT_PATH/.env

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install Fail2ban  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    if ! dpkg -l | grep -q "^ii  fail2ban "; then
        echo "Installing fail2ban..."
        sudo apt-get install -y fail2ban || { echo "Failed to install Fail2ban"; exit 1; }
    else
        echo "Fail2ban is already installed, skipping."
    fi

    # Create jail.local for custom Fail2ban configurations
    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5
action = %(action_)s

# SSH protection
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF

    # Enable and start Fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    # Enable log rotation for Fail2ban logs
    echo "/var/log/fail2ban.log {
    rotate 7
    daily
    compress
    missingok
    notifempty
}" > /etc/logrotate.d/fail2ban

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Ensure services will start on boot ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Make services start on boot
    sudo systemctl enable frankenphp cloudflared ufw fail2ban || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install the upgraded DigitalOcean Metrics Agent ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Install the DigitalOcean Metrics Agent
    echo "Installing the DigitalOcean Metrics Agent..."
    curl -sSL https://repos.insights.digitalocean.com/install.sh | sudo bash || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set custom MOTD  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Customize the Message of the Day (MOTD)
    cat <<EOF > /etc/motd

### CUSTOM SES API CONFIGURATION IS INSTALLED ###

Welcome to your Caddy (FrankenPHP) API Droplet! 

Your server has been configured with the following: 
 - Caddy web server with Brotli and Gzip compression 
 - FrankenPHP for optimized PHP performance with worker mode 
 - Cloudflare Argo Tunnel installed (manual login required)
 - Real IP and Trusted Proxy configurations for Cloudflare 
 - Automatic TLS with Cloudflare DNS
 - fail2ban for SSH protection
 - Automatic logs cleanup script
 - Error reporting configured with Sentry (DSN: $SENTRY_DSN)
 - Document root: $DOCUMENT_ROOT_PATH
 - Utilities located at: $UTILITIES_PATH
 - Composer packages installed in: $COMPOSER_PATH 
 
Server FQDN: $SERVER_FQDN

Next Steps: 
 1. Configure your Cloudflare Argo Tunnel:
        - Create a new tunnel at https://one.dash.cloudflare.com/$CF_ACCOUNT_ID/networks/tunnels/add
        - Name the tunnel "$SERVER_HOSTNAME"
        - Set the operating system to "Debian", and architecture to "64-bit"
        - Copy the `sudo cloudflared service install` script (it will be titled "If you already have cloudflared installed on your machine:")
        - Run the script on your server and follow the prompts
        - Profit!
 2. Place your public files in $PUBLIC_ROOT_PATH
 3. Ensure your PHP files include Sentry for error reporting
 4. Access your server through your configured Cloudflare domain

A dynamic utility import has also been installed. Import utilities in your 
PHP scripts using `require_once '@utilities/utility.php'`

This server has been secured with a firewall. To allow additional ports, run:
    > sudo ufw allow <port_number>

Run the following command to remove this custom MOTD:

    > sed -i '/### CUSTOM SES API CONFIGURATION IS INSTALLED ###/,\$d' /etc/motd

EOF

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Cleanup Activities ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Remove temporary files
    echo "Cleaning up temporary files..." ||
    rm -rf /tmp/* || true
    
    # Remove Apache2 if it's installed
    sudo systemctl stop apache2 || true
    sudo systemctl disable apache2 || true
    sudo apt-get purge -y apache2 apache2-utils apache2-bin apache2.2-common || true
    sudo rm -rf /etc/apache2 || true
    dpkg -l | grep apache2 || true

    # Clear the APT cache
    echo "Clearing APT cache..."
    sudo apt-get clean || true

    # Rotate logs to ensure that new log rotation policies take effect immediately
    echo "Rotating logs..."
    logrotate -f /etc/logrotate.conf || true
    
    # Remove downloaded packages that are no longer required
    echo "Removing unnecessary packages..."
    sudo apt-get autoremove -y || true

    echo "Cleanup complete."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ All done!  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Initialization complete. Your server is configured with Caddy, FrankenPHP, Sentry, and Cloudflare Argo Tunnel."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Schedule a Server Restart in 10 Seconds ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "The server will restart in 10 seconds to apply all changes."
    sleep 1
    echo "10..."
    sleep 1
    echo "9..."
    sleep 1
    echo "8..."
    sleep 1
    echo "7..."
    sleep 1
    echo "6..."
    sleep 1
    echo "5..."
    sleep 1
    echo "4..."
    sleep 1
    echo "3..."
    sleep 1
    echo "2..."
    sleep 1
    echo "1..."
    sleep 1
    echo "Goodbye!"
    
    sudo shutdown -r now "Restarting server to apply changes..."
