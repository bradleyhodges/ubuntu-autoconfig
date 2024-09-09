DOCUMENT_ROOT_PATH="/var/www" # This is where your files will live :)
COMPOSER_PATH="$DOCUMENT_ROOT_PATH/composer" # This is where Composer will be installed

echo "Global Composer configuration set to install packages to $COMPOSER_PATH/vendor."

    # Set the COMPOSER_VENDOR_DIR environment variable
    echo "Setting COMPOSER_VENDOR_DIR environment variable..."
    export COMPOSER_VENDOR_DIR="$COMPOSER_PATH/vendor"

    # Add this to the shell profile to persist the environment variable
    if ! grep -q "export COMPOSER_VENDOR_DIR=" ~/.bashrc; then
        echo 'export COMPOSER_VENDOR_DIR="'$COMPOSER_VENDOR_DIR'"' >> ~/.bashrc
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
                command composer require --working-dir="'$COMPOSER_PATH'" --optimize-autoloader "${@:2}"
            else
                command composer "$@"
            fi
        }' >> ~/.bashrc
    fi

    # Update the PHP include_path to include the Composer directory
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$COMPOSER_PATH\"|" /etc/php/*/fpm/php.ini || true
    sed -i "s|;include_path = \".:/usr/share/php\"|include_path = \".:/usr/share/php:$COMPOSER_PATH\"|" /etc/php/*/cli/php.ini || true

    echo "Composer setup completed with global configuration and environment variable."
