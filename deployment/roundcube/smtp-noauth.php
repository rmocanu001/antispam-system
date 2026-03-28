<?php
// Disable SMTP auth — Postfix accepts from mynetworks without credentials
$config['smtp_user'] = '';
$config['smtp_pass'] = '';
$config['smtp_auth_type'] = null;
