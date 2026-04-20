<?php
$config['plugins'] = [];
$config['log_driver'] = 'stdout';
$config['zipdownload_selection'] = true;
$config['enable_spellcheck'] = false;

// Load Docker-generated config (IMAP host, db_dsnw, etc.)
if (file_exists(__DIR__ . '/config.docker.inc.php')) {
    include __DIR__ . '/config.docker.inc.php';
}

// ---- SMTP submission with user credentials ----
// Postfix port 587, SASL authenticated via Dovecot.
// %u = IMAP login username, %p = IMAP login password.
$config['smtp_server']    = 'postfix';
$config['smtp_port']      = 587;
$config['smtp_user']      = '%u';
$config['smtp_pass']      = '%p';
$config['smtp_auth_type'] = 'LOGIN';

// Disable strict TLS verification for self-signed cert on internal network
$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer'      => false,
        'verify_peer_name' => false,
    ],
];
$config['imap_conn_options'] = [
    'ssl' => [
        'verify_peer'      => false,
        'verify_peer_name' => false,
    ],
];
