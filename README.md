# DigitalOcean API Server Initialization Script

## Overview
This script is designed to automate the initialization of a new DigitalOcean droplet designated as an API server. It configures the server with the following technologies:

- **FrankenPHP** (Caddy server optimized for PHP)
- **PHP** with necessary extensions
- **Sentry** for error monitoring
- **Cloudflare Argo Tunnel** for secure tunneling
- **Composer** for PHP dependency management
- **Fail2ban** for security
- **Firewall (UFW)** setup
- **System Performance Tweaks**
- **Automatic Cloudflare IP Whitelisting**

This script is intended for internal use only. Ensure that sensitive information such as API tokens and passwords are handled securely.

## Prerequisites
- A newly created DigitalOcean droplet running Ubuntu.
- Sudo privileges are required to execute this script.
- Replace all placeholder values (e.g., `CF_API_TOKEN`, `SENTRY_DSN`, etc.) with actual values before running the script.

## Execution Instructions
Make the script executable:
```bash
chmod +x ./setup-server.sh
```

Run the script with sudo:
```bash
sudo ./setup-server.sh
```

## Key Components
### Configuration Parameters
Ensure the following parameters are set correctly before executing the script:
- **SERVER_EMAIL**: Sysadmin email address for Let's Encrypt notifications.
- **CF_API_TOKEN**: Cloudflare API token with DNS, Tunnel, and Certificate permissions.
- **CF_ACCOUNT_ID**: Cloudflare account ID.
- **CF_ZONE_ID**: Cloudflare Zone ID for the associated domain.
- **SENTRY_DSN**: Sentry Data Source Name (DSN) for error reporting.
- **SERVER_FQDN**: Fully Qualified Domain Name for the server.
- **DOCUMENT_ROOT_PATH**: Path where server files will be stored.

### Main Features
1. **Package Installation**
   - Updates existing packages.
   - Installs necessary dependencies (e.g., `curl`, `git`, `php`, etc.).

2. **FrankenPHP Installation**
   - Downloads and installs the FrankenPHP binary.
   - Configures a systemd service to manage FrankenPHP.

3. **Composer Installation**
   - Installs Composer, a PHP dependency manager.
   - Sets up a custom vendor directory for PHP dependencies.

4. **Cloudflare Argo Tunnel Setup**
   - Installs the Cloudflare Argo Tunnel client (`cloudflared`).
   - Configures the firewall (UFW) to allow Cloudflare traffic and critical ports.

5. **Security Enhancements**
   - Configures `Fail2ban` to protect the server from brute-force attacks.
   - Sets up automatic log rotation for `Fail2ban` and Cloudflare logs.
   - Ensures that critical files (e.g., `.env`, logs) are secured with appropriate permissions.

6. **System Performance Optimizations**
   - Adjusts TCP settings for better network performance.
   - Disables Transparent Huge Pages (THP) for improved memory management.
   - Increases file descriptor limits and optimizes CPU performance.

7. **Cron Jobs**
   - Schedules a cron job to automatically update Cloudflare IP addresses.
   - Creates a daily cleanup script to remove old temporary files and rotate logs.

8. **Final Touches**
   - Configures a custom Message of the Day (MOTD) to provide server information and next steps for administrators.
   - Schedules a server restart at the end of the script to apply all changes.

## Logging
All script output is logged to `/root/.initialisation-script.log` for debugging and auditing purposes.

## Post-Setup Instructions
After the script has completed:
1. **Cloudflare Tunnel Configuration**: Follow the instructions in the custom MOTD to complete the setup of the Cloudflare Argo Tunnel.
2. **Deployment**: Place your public files in the `public` directory (`$DOCUMENT_ROOT_PATH/public`).
3. **Error Monitoring**: Ensure your PHP applications use the Sentry DSN configured in the script for error reporting.

To remove the custom MOTD, run the following command:
```bash
sed -i '/### CUSTOM SES API CONFIGURATION IS INSTALLED ###/,$d' /etc/motd
```

## Troubleshooting
If any issues occur during setup:
- Review the log file at `/root/.initialisation-script.log` for error messages.
- Ensure all required configuration parameters are correctly set before running the script.
