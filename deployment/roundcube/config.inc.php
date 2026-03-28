<?php
$config['plugins'] = [];
$config['log_driver'] = 'stdout';
$config['zipdownload_selection'] = true;
$config['enable_spellcheck'] = false;

// Load Docker-generated config (IMAP/SMTP host, db, etc.)
if (file_exists(__DIR__ . '/config.docker.inc.php')) {
    include(__DIR__ . '/config.docker.inc.php');
}

// Disable SMTP auth — Postfix accepts mynetworks without credentials
$config['smtp_user'] = '';
$config['smtp_pass'] = '';
$config['smtp_auth_type'] = null;
