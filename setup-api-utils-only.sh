#!/bin/bash

# This script sets up the SES PHP API Utilities, configures Composer,
# installs necessary dependencies, and configures the environment
# for PHP and related services on an Ubuntu server.

# Echo commands to the console for debugging purposes
set -x

# You can make this script executable by running:
#   > chmod +x ./setup-api-utils-only.sh
# And then run it with:
#   > sudo ./setup-api-utils-only.sh
# Or, run it all at once:
#   > chmod +x ./setup-api-utils-only.sh && sudo ./setup-api-utils-only.sh

# *********************************************************** #
# *                Configuration Parameters                 * #
# *********************************************************** #
# Update these variables to suit your environment
DOCUMENT_ROOT_PATH="/var/www" # This is where your files will live :)
ALLOW_FILE_UPLOADS="false" # Set to "true" to allow file uploads, "false" to disallow

# Things you probably don't need to change, but you can if you want to:
PUBLIC_ROOT_PATH="$DOCUMENT_ROOT_PATH/public" # This is where your public files live
UTILITIES_PATH="$DOCUMENT_ROOT_PATH/utilities" # This is where your utilities live
COMPOSER_PATH="$DOCUMENT_ROOT_PATH/composer" # This is where Composer will be installed
COMPOSER_AUTOLOAD_PATH="$COMPOSER_PATH/vendor/autoload.php" # This is where Composer autoload will be generated
ALLOW_PHP_REQUIRE_OUTSIDE_OF_DOCUMENT_ROOT="false" # Set to "true" to allow PHP require/require_once outside of the document root, "false" to disallow


# Do not modify anything beyond this point unless necessary
# *********************************************************** #

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Get the configuration script ready. Set up logging, etc.  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
# Ensure script is run as root or with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or use sudo."
    exit 1
fi

# Redirect output to both console and log file
exec > >(tee -a /.api-utils-setup.log) 2>&1 

# Exit the script on any error
set -e

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Update existing packages and get new dependencies  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Update and upgrade all packages to their latest versions
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update || { echo "Package update/upgrade failed"; exit 1; }

    # Install necessary packages if not already installed
    dependencies=(curl cron git openssl)
    for pkg in "${dependencies[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            sudo apt-get install -y "$pkg" || { echo "Failed to install $pkg"; exit 1; }
        else
            echo "$pkg is already installed, skipping."
        fi
    done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Set up environment variables  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Path to the .env file where environment variables will be stored
    ENV_FILE="$DOCUMENT_ROOT_PATH/.env"

    # Environment variables to set
    declare -A VARS=(
        ["DOCUMENT_ROOT_PATH"]="$DOCUMENT_ROOT_PATH"
        ["COMPOSER_AUTOLOAD_PATH"]="$COMPOSER_AUTOLOAD_PATH"
        ["UTILITIES_PATH"]="$UTILITIES_PATH"
        ["ENFORCE_SAFE_REQUIRES"]="$ALLOW_PHP_REQUIRE_OUTSIDE_OF_DOCUMENT_ROOT"
    )

    # Function to update or append a variable in the .env file
    update_or_append() {
        local var_name=$1
        local var_value=$2

        # Check if the variable already exists in the .env file and update it
        if grep -q "^$var_name=" "$ENV_FILE"; then
            sed -i "s|^$var_name=.*|$var_name=$var_value|" "$ENV_FILE"
        else
            # Append the variable if it does not exist
            echo "$var_name=$var_value" >> "$ENV_FILE"
        fi
    }

    # Check if the .env file exists
    if [ -f "$ENV_FILE" ]; then
        echo ".env file exists. Updating values..."
        for var_name in "${!VARS[@]}"; do
            update_or_append "$var_name" "${VARS[$var_name]}"
        done
    else
        echo ".env file does not exist. Creating it with values..."
        for var_name in "${!VARS[@]}"; do
            echo "$var_name=${VARS[$var_name]}" >> "$ENV_FILE"
        done
    fi
    echo "Environment setup complete."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install Composer  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set COMPOSER_ALLOW_SUPERUSER to suppress warnings when running as root
    export COMPOSER_ALLOW_SUPERUSER=1

    # Install Composer if it is not already installed
    if ! command -v composer &> /dev/null; then
        echo "Installing Composer..."

        # Download and install Composer
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

        # Clear the Composer cache
        composer clear-cache

        # Update Composer to the latest version
        composer self-update --2

        # Verify Composer installation
        if command -v composer &> /dev/null; then
            echo "Composer is up to date. Version: $(composer --version)"
        else
            echo "Failed to update Composer."
            exit 1
        fi
    fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install SES PHP API Utilities  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Set up Composer configuration for the utilities
    COMPOSER_JSON_PATH="$UTILITIES_PATH/composer.json"
    CUSTOM_VENDOR_DIR="$COMPOSER_PATH/vendor"

    # Configure the deployignore file path
    DEPLOYIGNORE_FILE="$UTILITIES_PATH/.deployignore"

    # Ensure Git trusts the utilities directory
    git config --global --add safe.directory "$UTILITIES_PATH"

    # Configure Composer to use the custom vendor directory
    export COMPOSER_VENDOR_DIR="$CUSTOM_VENDOR_DIR"
    echo 'export COMPOSER_VENDOR_DIR="$CUSTOM_VENDOR_DIR"' >> ~/.profile

    # Clone the SES PHP API Utilities repository if not already cloned
    if [ ! -d "$UTILITIES_PATH/.git" ]; then
        echo "Cloning SES PHP API Utilities from GitHub..."
        git clone --no-checkout https://github.com/dfes-ses/common-api-utilities.git "$UTILITIES_PATH" || { echo "Failed to clone SES API Utilities"; exit 1; }
    else
        echo "SES PHP API Utilities repository already cloned, pulling the latest changes..."
        cd "$UTILITIES_PATH" && git fetch --all || { echo "Failed to fetch updates from GitHub"; exit 1; }
    fi

    cd "$UTILITIES_PATH"

    # Configure sparse-checkout based on the deployignore file
    git config core.sparseCheckout true
    echo "/*" > .git/info/sparse-checkout

    if [ -f ".deployignore" ]; then
        while IFS= read -r pattern; do
            # Remove leading/trailing whitespace and skip empty lines and comments
            pattern=$(echo "$pattern" | xargs)
            if [ -n "$pattern" ] && [ "${pattern:0:1}" != "#" ]; then
                echo "!$pattern" >> .git/info/sparse-checkout
            fi
        done < .deployignore
    fi

    # Check out the necessary files
    git checkout

    # Create composer.json if it doesn't exist
    if [ ! -f "$COMPOSER_JSON_PATH" ]; then
        echo "Creating composer.json with custom vendor directory..."
        cat <<EOF > "$COMPOSER_JSON_PATH"
{
    "config": {
        "vendor-dir": "$CUSTOM_VENDOR_DIR"
    },
    "require": {}
}
EOF
    else
        echo "composer.json already exists. Ensuring custom vendor directory is set..."
        if ! grep -q '"vendor-dir":' "$COMPOSER_JSON_PATH"; then
            # Insert the vendor-dir configuration into the existing composer.json file
            sed -i '/"config": {/a \ \ \ \ "vendor-dir": "'"$CUSTOM_VENDOR_DIR"'",' "$COMPOSER_JSON_PATH"
        fi
    fi

    # Install Composer dependencies
    if composer install --ignore-platform-reqs --no-dev -a --optimize-autoloader --no-interaction; then
        echo "Composer dependencies installed successfully."
    else
        echo "Failed to install Composer dependencies."
        exit 1
    fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Install a cron to maintain SES PHP API Utilities ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Create a script to update the SES PHP API Utilities repository
    cat <<EOF > "$UTILITIES_PATH/update-repo.sh"
#!/bin/bash

# Ensure Git trusts the utilities directory
git config --global --add safe.directory "$UTILITIES_PATH"

# Change to the utilities directory
cd "$UTILITIES_PATH" || exit 1

# Pull the latest changes
git fetch --all || exit 1
git reset --hard origin/main || exit 1
git clean -fd || exit 1

# Read .deployignore and remove ignored files
if [ -f "$DEPLOYIGNORE_FILE" ]; then
    while IFS= read -r pattern; do
        if [ -n "\$pattern" ] && [ "\$pattern" != "#" ]; then
            # Remove ignored files
            find . -type f -name "\$pattern" -delete
        fi
    done < "$DEPLOYIGNORE_FILE"
fi
EOF

    # Make the update script executable
    chmod +x "$UTILITIES_PATH/update-repo.sh"

    # Set up a cron job to pull the latest changes from the repository every hour
    CRON_JOB="@hourly bash $UTILITIES_PATH/update-repo.sh > /dev/null 2>&1"
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "Configured SES PHP API Utilities periodic refresh script"
    
# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Configure PHP  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Function to update php.ini file with required settings
    update_php_ini() {
        local php_ini_file=$1
        local allow_uploads=$2

        # Enable the fileinfo extension
        if grep -q "^;extension=fileinfo" "$php_ini_file"; then
            sed -i "s/^;extension=fileinfo/extension=fileinfo/" "$php_ini_file"
        elif ! grep -q "^extension=fileinfo" "$php_ini_file"; then
            echo "extension=fileinfo" >> "$php_ini_file"
        fi

        # Set the file_uploads directive based on ALLOW_FILE_UPLOADS value
        if [ "$allow_uploads" = "true" ]; then
            sed -i "s/^file_uploads = .*/file_uploads = On/" "$php_ini_file"
            sed -i "s/^upload_max_filesize = .*/upload_max_filesize = 50M/" "$php_ini_file"
            sed -i "s/^post_max_size = .*/post_max_size = 50M/" "$php_ini_file"
        else
            sed -i "s/^file_uploads = .*/file_uploads = Off/" "$php_ini_file"
        fi
    }

    # Find and update all relevant php.ini files
    find /etc/php -type f -name "php.ini" | while read -r php_ini; do
        echo "Updating $php_ini..."
        update_php_ini "$php_ini" "$ALLOW_FILE_UPLOADS"
    done

    # Reload PHP-FPM service to apply changes
    if systemctl is-active --quiet php-fpm; then
        echo "Reloading PHP-FPM service..."
        systemctl reload php-fpm || true
    fi
    echo "PHP configuration updated successfully."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ Cleanup Activities ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    # Remove temporary files
    echo "Cleaning up temporary files..."
    rm -rf /tmp/* || true

    # Clear APT cache to free up space
    echo "Clearing APT cache..."
    sudo apt-get clean || true

    # Remove downloaded packages that are no longer required
    echo "Removing unnecessary packages..."
    sudo apt-get autoremove -y || true

    echo "Cleanup complete."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~ All done!  ~~~~~~~~~~~~~~~~~~~~~~~~~~ #
    echo "Setup complete. You can now use the SES PHP API Utilities at $UTILITIES_PATH. Please restart your server for the changes to take effect."