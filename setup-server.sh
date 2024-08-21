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

# if you're having issues with `sudo: unable to execute ./setup-server.sh: No such file or directory`, 
# it may be a line endings issue. Fix with dos2unit:
#   > sudo apt-get install dos2unix -y
#   > dos2unix ./setup-server.sh

# *********************************************************** #
# *     Configuration parameters - please set these now     * #
# *********************************************************** #
# Things you definitely need to check and change if necessary:
SERVER_EMAIL="sysadmin@wases.com.au" 
CF_ACCOUNT_ID="26801e6068adefb82b51e4c3fe327105" # Replace with your Cloudflare Account ID
CF_ZONE_ID="79df1b429fbc516754f7cf9d297fdcbf" # Replace with your Cloudflare website's Zone ID
SENTRY_DSN="" # Replace with your Sentry DSN 
SERVER_FQDN="" # Replace with your server's public hostname (FQDN) - eg. api.vitalis.wases.com.au"
DOCUMENT_ROOT_PATH="/var/www" # This is where your files will live :)
ALLOW_FILE_UPLOADS="false" # Set to "true" to allow file uploads, "false" to disallow

# Things you probably don't need to change, but you can if you want to:
LOGS_PATH="/var/log/caddy" # This is where all of the logs produced by the server will be stored
PUBLIC_ROOT_PATH="$DOCUMENT_ROOT_PATH/public" # This is where your public files will live
UTILITIES_PATH="$DOCUMENT_ROOT_PATH/utilities" # This is where your utilities will live
COMPOSER_PATH="$DOCUMENT_ROOT_PATH/composer" # This is where Composer will be installed
UPLOADS_PATH="$DOCUMENT_ROOT_PATH/uploads" # This is where PHP will be instructed to temporarily store uploaded files
ALLOW_PHP_REQUIRE_OUTSIDE_OF_DOCUMENT_ROOT="false" # Set to "true" to allow PHP require/require_once outside of the document root, "false" to disallow

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
    sudo apt-get update && sudo apt upgrade -y && sudo apt-get dist-upgrade -y || { echo "Package update/upgrade failed"; exit 1; }

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
    directories=($DOCUMENT_ROOT_PATH $PUBLIC_ROOT_PATH $UTILITIES_PATH $COMPOSER_PATH /etc/caddy /var/lib/caddy $LOGS_PATH)
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
    sudo chown -R caddyuser:caddyuser $DOCUMENT_ROOT_PATH /etc/caddy /var/lib/caddy $LOGS_PATH

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up environment variables  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set up environment variables
    cat <<EOF > $DOCUMENT_ROOT_PATH/.env
DOCUMENT_ROOT_PATH=$DOCUMENT_ROOT_PATH
COMPOSER_AUTOLOAD_PATH=$COMPOSER_AUTOLOAD_PATH
UTILITIES_PATH=$UTILITIES_PATH
CF_ACCOUNT_ID=$CF_ACCOUNT_ID
CF_ZONE_ID=$CF_ZONE_ID
SERVER_FQDN=$SERVER_FQDN
LOGS_PATH=$LOGS_PATH
FORCE_SAFE_REQUIRES=$ALLOW_PHP_REQUIRE_OUTSIDE_OF_DOCUMENT_ROOT
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

    # Find and update all in-scope php.ini files
    find /etc/php -type f -name "php.ini" | while read -r PHP_INI; do
        echo "Updating $PHP_INI..."

        # Backup the existing php.ini
        cp "$PHP_INI" "$PHP_INI.bak_$(date +%F_%T)" || true
        echo "Backup of php.ini created at $PHP_INI.bak_$(date +%F_%T)"

        # Security and performance settings for php.ini
        echo "Applying security and performance settings..."

        sed -i 's/^expose_php\s*=.*/expose_php = Off/' "$PHP_INI" || true
        sed -i 's/^display_errors\s*=.*/display_errors = Off/' "$PHP_INI" || true
        sed -i 's/^file_uploads\s*=.*/file_uploads = On/' "$PHP_INI" || true
        sed -i 's/^upload_max_filesize\s*=.*/upload_max_filesize = 1M/' "$PHP_INI" || true
        sed -i 's|^session.save_path\s*=.*|session.save_path = "'$DOCUMENT_ROOT_PATH'/session"|' "$PHP_INI" || true
        sed -i 's|^upload_tmp_dir\s*=.*|upload_tmp_dir = "'$DOCUMENT_ROOT_PATH'/session"|' "$PHP_INI" || true
        sed -i 's/^allow_url_fopen\s*=.*/allow_url_fopen = Off/' "$PHP_INI" || true
        sed -i 's/^allow_url_include\s*=.*/allow_url_include = Off/' "$PHP_INI" || true

        # Enable error logging
        sed -i 's/^log_errors\s*=.*/log_errors = On/' "$PHP_INI" || true
        sed -i 's/^html_errors\s*=.*/html_errors = Off/' "$PHP_INI" || true  # Disable HTML errors
        sed -i 's/^display_errors\s*=.*/display_errors = Off/' "$PHP_INI" || true  # Disable displaying errors to the user
        sed -i 's/^error_reporting\s*=.*/error_reporting = E_ALL/' "$PHP_INI" || true  # Report all errors
        
        # Harden session security
        sed -i 's/^session.cookie_httponly\s*=.*/session.cookie_httponly = 1/' "$PHP_INI" || true
        sed -i 's/^session.cookie_secure\s*=.*/session.cookie_secure = 1/' "$PHP_INI" || true
        sed -i 's/^session.use_strict_mode\s*=.*/session.use_strict_mode = 1/' "$PHP_INI" || true
        sed -i 's/^session.use_only_cookies\s*=.*/session.use_only_cookies = 1/' "$PHP_INI" || true
        sed -i 's/^session.sid_bits_per_character\s*=.*/session.sid_bits_per_character = 6/' "$PHP_INI" || true  # Increase session ID entropy
        sed -i 's/^session.sid_length\s*=.*/session.sid_length = 48/' "$PHP_INI" || true  # Increase session ID length
        sed -i 's/^session.hash_function\s*=.*/session.hash_function = sha512/' "$PHP_INI" || true  # Use SHA-512 for session hashing
        sed -i 's/^session.hash_bits_per_character\s*=.*/session.hash_bits_per_character = 6/' "$PHP_INI" || true  # Increase session hash entropy
        sed -i 's/^session.cookie_samesite\s*=.*/session.cookie_samesite = Strict/' "$PHP_INI" || true  # Prevent CSRF attacks
        
        # Additional performance tuning
        sed -i 's/^memory_limit\s*=.*/memory_limit = 256M/' "$PHP_INI" || true
        sed -i 's/^max_execution_time\s*=.*/max_execution_time = 30/' "$PHP_INI" || true
        sed -i 's/^max_input_time\s*=.*/max_input_time = 30/' "$PHP_INI" || true
        sed -i 's/^post_max_size\s*=.*/post_max_size = 1M/' "$PHP_INI" || true

        # Set the upload_tmp_dir to a secure location
        sed -i 's|^upload_tmp_dir\s*=.*|upload_tmp_dir = "'$DOCUMENT_ROOT_PATH'"|' "$PHP_INI" || true
        chmod 700 "$UPLOADS_PATH" || true # Ensure the directory is only accessible by the web server
        
        # Disable dangerous PHP functions
        sed -i 's/^disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,popen,proc_open,proc_close,proc_get_status,proc_terminate,pcntl_exec,show_source,parse_ini_file,phpinfo,symlink,dl/' "$PHP_INI" || true

        # Additional security measures
        echo "cgi.fix_pathinfo = 0" >> "$PHP_INI" || true # Prevent path disclosure vulnerabilities

        echo "Security and performance settings applied successfully."

        # Enable required PHP extensions
        for ext in curl ffi mbstring exif openssl mysqli; do
            if ! grep -q "^extension=$ext" "$PHP_INI"; then
                echo "Enabling $ext extension in: $PHP_INI"
                echo "extension=$ext" | sudo tee -a "$PHP_INI" > /dev/null
            else
                echo "$ext extension is already enabled in: $PHP_INI"
            fi
        done

        echo "Extensions have been enabled in: $PHP_INI"
    done

    # Update PHP to log errors to Caddy's error log
    sed -i "s|;*log_errors =.*|log_errors = On|" /etc/php/*/fpm/php.ini || true
    sed -i "s|;*error_log =.*|error_log = $LOGS_PATH/error.log|" /etc/php/*/fpm/php.ini || true

    sed -i "s|;*log_errors =.*|log_errors = On|" /etc/php/*/cli/php.ini || true
    sed -i "s|;*error_log =.*|error_log = $LOGS_PATH/error.log|" /etc/php/*/cli/php.ini || true

    # Reload PHP-FPM to apply changes (if applicable)
    php_fpm_service=$(systemctl list-units --type=service --state=running | grep -oP 'php[0-9]+\.[0-9]+-fpm\.service' | head -n 1)

    if [ -n "$php_fpm_service" ]; then
        echo "Reloading PHP-FPM service: $php_fpm_service"
        systemctl reload "$php_fpm_service" || true
    else
        echo "No active PHP-FPM service found. Please manually reload your PHP service."
    fi

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
Environment=PHPRC=$PHP_INI

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd to apply the new service file
    sudo systemctl daemon-reload

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

    # Configure global composer settings
    COMPOSER_CONFIG_DIR="$HOME/.composer"
    mkdir -p "$COMPOSER_CONFIG_DIR"

    cat > "$COMPOSER_CONFIG_DIR/config.json" <<EOL
{
    "config": {
        "vendor-dir": "$COMPOSER_PATH/vendor"
    }
}
EOL

    echo "Global Composer configuration set to install packages to $COMPOSER_PATH/vendor."

    # Set the COMPOSER_VENDOR_DIR environment variable
    echo "Setting COMPOSER_VENDOR_DIR environment variable..."
    export COMPOSER_VENDOR_DIR="$COMPOSER_PATH/vendor"

    # Add this to the shell profile to persist the environment variable
    if ! grep -q "export COMPOSER_VENDOR_DIR=" ~/.bashrc; then
        echo 'export COMPOSER_VENDOR_DIR="/var/www/composer/vendor"' >> ~/.bashrc
    fi

    # Replace composer require with custom flags but leave other composer commands unaffected
    composer() {
        if [ "$1" == "require" ]; then
            command composer require --working-dir="$COMPOSER_PATH" --optimize-autoloader "${@:2}"
        else
            command composer "$@"
        fi
    }

    # Add the function to the shell profile to persist the behavior
    if ! grep -q "function composer()" ~/.bashrc; then
        echo 'function composer() {
            if [ "$1" == "require" ]; then
                command composer require --working-dir="$COMPOSER_PATH" --optimize-autoloader "${@:2}"
            else
                command composer "$@"
            fi
        }' >> ~/.bashrc
    fi

    # Update the PHP include_path to include the Composer directory
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$COMPOSER_PATH\"|" /etc/php/*/fpm/php.ini || true
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$COMPOSER_PATH\"|" /etc/php/*/cli/php.ini || true

    echo "Composer setup completed with global configuration and environment variable."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install SES PHP API Manager  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set COMPOSER_ALLOW_SUPERUSER to suppress warnings when running as root
    export COMPOSER_ALLOW_SUPERUSER=1

    # cd to the composer directory
    cd "$COMPOSER_PATH"

    # Initialise Composer in the Composer directory
    composer init \
        --require="bradleyhodges/api-manager:dev-main" \
        --stability="dev" \
        --working-dir="$COMPOSER_PATH" \
        --no-interaction
        
    # Install the dependencies
    composer install --ignore-platform-reqs --optimize-autoloader --no-interaction

    echo "Composer dependencies installed successfully."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install a cron to maintain SES PHP API Manager  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Create the update script
    cat <<EOF > "$DOCUMENT_ROOT_PATH/update-api-manager.sh"
#!/bin/bash

# Set COMPOSER_ALLOW_SUPERUSER to suppress warnings when running as root
export COMPOSER_ALLOW_SUPERUSER=1

# cd to the composer directory
cd "$COMPOSER_PATH" || exit 1

# Update the API Manager to the latest version
if composer update bradleyhodges/api-manager --ignore-platform-reqs --optimize-autoloader --no-interaction; then
    echo "\$(date): API Manager updated successfully."
else
    echo "\$(date): Failed to update API Manager."
    exit 1
fi
EOF

    # Make the update script executable
    chmod +x "$DOCUMENT_ROOT_PATH/update-api-manager.sh"

    # Set up a cron job to run the update script daily
    CRON_JOB="@daily bash $DOCUMENT_ROOT_PATH/update-api-manager.sh > /dev/null 2>&1"

    # Check if the cron job is already set, if not, add it
    (crontab -l | grep -F "$CRON_JOB") || (crontab -l ; echo "$CRON_JOB") | crontab -
    echo "Configured SES PHP API Manager to automatically check for updates daily."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Configure PHP for Caddy  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Function to update php.ini file
    update_php_ini() {
        local php_ini_file=$1
        local allow_uploads=$2

        # Enable fileinfo extension
        if grep -q "^;extension=fileinfo" "$php_ini_file"; then
            sed -i "s/^;extension=fileinfo/extension=fileinfo/" "$php_ini_file"
        elif ! grep -q "^extension=fileinfo" "$php_ini_file"; then
            echo "extension=fileinfo" >> "$php_ini_file"
        fi

        # Set file_uploads directive based on ALLOW_FILE_UPLOADS value
        if [ "$allow_uploads" = "true" ]; then
            sed -i "s/^file_uploads = .*/file_uploads = On/" "$php_ini_file"
            sed -i "s/^upload_max_filesize = .*/upload_max_filesize = 50M/" "$php_ini_file"
            sed -i "s/^post_max_size = .*/post_max_size = 50M/" "$php_ini_file"
        else
            sed -i "s/^file_uploads = .*/file_uploads = Off/" "$php_ini_file"
        fi

        # Apply additional optimizations
        sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "$php_ini_file"
    }

    # Find and update all relevant php.ini files
    find /etc/php -type f -name "php.ini" | while read -r php_ini; do
        echo "Updating $php_ini..."
        update_php_ini "$php_ini" "$ALLOW_FILE_UPLOADS"
    done

    # Reload PHP-FPM service to apply the changes
    if systemctl is-active --quiet php-fpm; then
        echo "Reloading PHP-FPM service..."
        systemctl reload php-fpm
    fi

    echo "PHP configuration updated successfully."

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
    # Global options
    email $SERVER_EMAIL          # Set your email for Let's Encrypt notifications
    auto_https off               # Disable automatic HTTP-01 challenges, as you are using custom TLS certificates
    frankenphp                   # Enable FrankenPHP module for PHP handling

    servers {
        protocols h1 h2 h3        # Enable HTTP/1, HTTP/2, and HTTP/3 (QUIC) protocols
    }

    # Configure logging at the global level
    log {
        level ERROR               # Set log level to ERROR to capture only error logs
        output file $LOGS_PATH/error.log  # Log errors to a specified file
    }
}

# Site-specific configuration
$SERVER_FQDN {
    # Serve files from the public directory
    root * $PUBLIC_ROOT_PATH

    # Enable PHP support using FrankenPHP
    php_server

    # Compression settings
    encode zstd br gzip            # Enable Zstandard, Brotli, and gzip compression

    # Security headers for improved security
    header {
        Strict-Transport-Security max-age=31536000; includeSubDomains; preload;  # Enforce HTTPS for 1 year
        X-Content-Type-Options nosniff                                           # Prevent MIME type sniffing
        X-Frame-Options DENY                                                     # Disallow embedding of this site in an iframe
        X-XSS-Protection "1; mode=block"                                         # Enable XSS protection in browsers
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"  # Define content policies
        Referrer-Policy "no-referrer"                                            # Prevent sending the referrer header
        Permissions-Policy "geolocation=(), microphone=(), camera=(), fullscreen=(), payment=()" # Restrict usage of browser features
    }

    # TLS configuration with the provided certificate and key
    tls $SSL_CERT_PATH $SSL_KEY_PATH   # Use the specified TLS certificate and key

    # Allow serving PHP files without the .php extension
    try_files {path} {path}/ {path}.php /index.php?{query}

    # Access log configuration
    log {
        output file $LOGS_PATH/access.log  # Log access requests to a specific file
        format console                     # Log format set to 'console'; can be changed to 'json' if preferred
    }

    # PHP file handling
    @phpFiles {
        path *.php                      # Match all PHP files
    }
    handle @phpFiles {
        try_files {path} =404            # Attempt to serve the PHP file, return 404 if not found
    }
}
EOF

    # Enable and start the FrankenPHP service
    sudo systemctl enable frankenphp
    sudo systemctl start frankenphp || { echo "Failed to start FrankenPHP service"; exit 1; }

    # Verify if the service is running
    sudo systemctl is-active --quiet frankenphp && echo "FrankenPHP service is running." || { echo "FrankenPHP service failed to start"; exit 1; }

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
    ufw allow OpenSSH
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
    (crontab -l ; echo "0 11 * * TUE /usr/bin/curl -sf https://www.cloudflare.com/ips-v4 -o /tmp/cloudflare-ips-v4.txt && /usr/bin/curl -sf https://www.cloudflare.com/ips-v6 -o /tmp/cloudflare-ips-v6.txt && for ip in \\\$(cat /tmp/cloudflare-ips-v4.txt); do ufw allow from \\\$ip to any port 80,443,7844 proto tcp; done && for ip in \\\$(cat /tmp/cloudflare-ips-v6.txt); do ufw allow from \\\$ip to any port 80,443,7844 proto tcp; done || echo 'Failed to update Cloudflare IPs' >> $LOGS_PATH/cloudflare-update.log") | crontab -

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Log rotation for Cloudflare update log ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "$LOGS_PATH/cloudflare-update.log {
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
logpath = $LOGS_PATH/auth.log
EOF

    # Enable and start Fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    # Enable log rotation for Fail2ban logs
    echo "$LOGS_PATH/fail2ban.log {
    rotate 7
    daily
    compress
    missingok
    notifempty
}" > /etc/logrotate.d/fail2ban

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install Chrony for Accurate Time Synchronization ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Installing chrony for time synchronization..."
    sudo apt-get install -y chrony || true

    # Configure chrony to use time.nist.gov and set advanced synchronization settings
    echo "Configuring chrony for accurate time synchronization..."
    sudo tee /etc/chrony/chrony.conf > /dev/null <<EOF
# Use NIST time server
server time.nist.gov iburst maxpoll 6

# Additional backup NTP servers for redundancy
pool ntp.ubuntu.com iburst
pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst

# Allow the system clock to be adjusted if the error is large
makestep 1.0 3

# Enable logging to monitor time adjustments
log tracking measurements statistics

# Record frequency changes and system performance metrics
driftfile /var/lib/chrony/chrony.drift
rtcsync

# Configuration for kernel clock discipline for better precision
rtcsync
rtconutc
EOF

    # Enable and start the chrony service
    sudo systemctl enable chrony || true
    sudo systemctl restart chrony || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set System Timezone to UTC ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Configuring the server to use UTC timezone..."
    sudo timedatectl set-timezone UTC || true
    sudo timedatectl set-ntp true || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Unattended Upgrades for Automatic Security Updates ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set the frontend to non-interactive to avoid prompts
    export DEBIAN_FRONTEND=noninteractive

    echo "Installing and enabling unattended-upgrades for automatic security updates..."

    # Install unattended-upgrades in non-interactive mode
    sudo apt-get install -y unattended-upgrades || true

    # Pre-seed the configuration to ensure it runs without prompts
    sudo debconf-set-selections <<< "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true"

    # Reconfigure unattended-upgrades with the pre-seeded configuration
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades || true

    # Enable automatic reboot after unattended upgrades, and append to the configuration
    echo "Unattended-Upgrade::Automatic-Reboot \"true\";" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Enabling TCP SYN Cookies for DDoS Protection ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Enabling TCP SYN Cookies for protection against SYN flood attacks..."
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf || true
    sysctl -p || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Additional security and performance configuration ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Disable core dumps to avoid exposing sensitive data
    echo "Disabling core dumps..."
    echo "* hard core 0" >> /etc/security/limits.conf || true

    # Enable randomizing memory space to prevent various attacks
    echo "Optimizing TCP settings for performance..."
    echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_rmem = 4096 87380 6291456" >> /etc/sysctl.conf || true
    echo "net.ipv4.tcp_wmem = 4096 65536 6291456" >> /etc/sysctl.conf || true
    sysctl -p || true
    
    # Disable USB storage to prevent unauthorized data transfer
    echo "Disabling USB ports..."
    echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/disable-usb-storage.conf || true

    # Enable I/O scheduler optimization for performance
    echo "Optimizing I/O scheduler..."
    echo 'noop' | sudo tee /sys/block/sda/queue/scheduler || true

    # Disable unnecessary services
    echo "Disabling unnecessary services..."
    sudo systemctl disable apache2 || true
    sudo systemctl disable avahi-daemon || true
    sudo systemctl disable cups || true
    sudo systemctl disable bluetooth || true
    sudo systemctl disable ModemManager || true
    sudo systemctl disable lxd || true

    # Configure swap for better memory management
    sudo fallocate -l 1G /swapfile || true
    sudo chmod 600 /swapfile || true
    sudo mkswap /swapfile || true
    sudo swapon /swapfile || true
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Ensure services will start on boot ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Make services start on boot
    sudo systemctl enable frankenphp cloudflared ufw fail2ban || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install the upgraded DigitalOcean Metrics Agent ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Install the DigitalOcean Metrics Agent
    echo "Installing the DigitalOcean Metrics Agent..."
    curl -sSL https://repos.insights.digitalocean.com/install.sh | sudo bash || true

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Create Custom PHP Stream Wrapper for app:// ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Creating custom PHP stream wrapper for 'at:/'."

    STREAM_WRAPPER_DIR="/etc/caddy/php-config"
    STREAM_WRAPPER_FILE="$STREAM_WRAPPER_DIR/init_stream_wrapper.php"

    # Create the directory if it doesn't exist
    mkdir -p "$STREAM_WRAPPER_DIR" || true

    # Create the PHP file that registers the custom stream wrapper
    cat <<EOF > "$STREAM_WRAPPER_FILE"
<?php
/**
 * Custom stream wrapper to map "app://path" to the DOCUMENT_ROOT_PATH.
 */

class AppStreamWrapper {
    private \$basePath;
    private \$handle;

    public function __construct() {
        // Set base path to the DOCUMENT_ROOT_PATH from the environment or a default value
        \$this->basePath = getenv('DOCUMENT_ROOT_PATH') ?: '$DOCUMENT_ROOT_PATH';
    }

    public function stream_open(\$path, \$mode, \$options, &\$opened_path) {
        \$filePath = \$this->resolveFilePath(\$path);

        // Check if the file exists before opening it
        if (!file_exists(\$filePath)) {
            return false;
        }

        \$this->handle = fopen(\$filePath, \$mode);
        return (bool) \$this->handle;
    }

    public function stream_read(\$count) {
        return fread(\$this->handle, \$count);
    }

    public function stream_write(\$data) {
        return fwrite(\$this->handle, \$data);
    }

    public function stream_close() {
        fclose(\$this->handle);
    }

    public function stream_eof() {
        return feof(\$this->handle);
    }

    public function stream_stat() {
        return fstat(\$this->handle);
    }

    public function url_stat(\$path, \$flags) {
        \$filePath = \$this->resolveFilePath(\$path);
        return @stat(\$filePath);
    }

    private function resolveFilePath(\$path) {
        return str_replace('app:/', \$this->basePath . '/', \$path);
    }
}

// Register the "app:" stream wrapper
stream_wrapper_register('app', 'AppStreamWrapper');
EOF

    # Ensure the file is owned by the appropriate user and has secure permissions
    chown caddyuser:caddyuser "$STREAM_WRAPPER_FILE"
    chmod 600 "$STREAM_WRAPPER_FILE"

    # Explicitly search for the PHP-FPM and CLI configuration files
    PHP_INI_FPM=$(find /etc/php -name php.ini | grep "/fpm/")
    PHP_INI_CLI=$(find /etc/php -name php.ini | grep "/cli/")

    # Update auto_prepend_file directive in PHP-FPM configuration file
    if [ -f "$PHP_INI_FPM" ]; then
        if grep -q '^auto_prepend_file' "$PHP_INI_FPM"; then
            sed -i "s|^auto_prepend_file.*|auto_prepend_file = \"$STREAM_WRAPPER_FILE\"|" "$PHP_INI_FPM" || true
        else
            echo "auto_prepend_file = \"$STREAM_WRAPPER_FILE\"" >> "$PHP_INI_FPM" || true
        fi
        echo "Updated $PHP_INI_FPM with auto_prepend_file = \"$STREAM_WRAPPER_FILE\""
    else
        echo "PHP-FPM configuration file not found."
    fi

    # Update auto_prepend_file directive in PHP-CLI configuration file
    if [ -f "$PHP_INI_CLI" ]; then
        if grep -q '^auto_prepend_file' "$PHP_INI_CLI"; then
            sed -i "s|^auto_prepend_file.*|auto_prepend_file = \"$STREAM_WRAPPER_FILE\"|" "$PHP_INI_CLI" || true
        else
            echo "auto_prepend_file = \"$STREAM_WRAPPER_FILE\"" >> "$PHP_INI_CLI" || true
        fi
        echo "Updated $PHP_INI_CLI with auto_prepend_file = \"$STREAM_WRAPPER_FILE\""
    else
        echo "PHP-CLI configuration file not found."
    fi

    # Reload PHP-FPM service to apply the changes
    php_fpm_service=$(systemctl list-units --type=service --state=running | grep -oP 'php[0-9]+\.[0-9]+-fpm\.service' | head -n 1)

    if [ -n "$php_fpm_service" ]; then
        echo "Reloading PHP-FPM service: $php_fpm_service"
        systemctl reload "$php_fpm_service" || true
    else
        echo "No active PHP-FPM service found. Please manually reload your PHP service."
    fi

    echo "Custom stream wrapper for 'at:/path' has been configured in $STREAM_WRAPPER_FILE."

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
PHP scripts using `require_once 'app://utilities/utility.php'`

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
