#!/bin/bash
# ============================================================
# Seed initial mail users via the account-admin API.
# Run after: docker-compose up -d
# Requires: curl
# ============================================================

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-changeme}"
API="http://localhost:8081/api/users"

create_user() {
    local email="$1"
    local pass="$2"
    echo -n "Creating $email ... "
    curl -s -o /dev/null -w "%{http_code}" \
         -u "$ADMIN_USER:$ADMIN_PASS" \
         -H "Content-Type: application/json" \
         -d "{\"email\":\"$email\",\"password\":\"$pass\"}" \
         "$API"
    echo
}

create_user "admin@igsu.local"   "AdminPass123!"
create_user "user1@igsu.local"   "UserPass123!"
create_user "test@igsu.local"    "TestPass123!"

echo "Done. Users can be managed at https://admin.igsu.local:8443"
