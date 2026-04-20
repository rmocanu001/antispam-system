-- ============================================================
-- IGSU Mail Server — MariaDB initialisation
-- ============================================================

CREATE DATABASE IF NOT EXISTS mailserver
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS roundcubemail
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ---- service accounts ----
CREATE USER IF NOT EXISTS 'dovecot'@'%'      IDENTIFIED BY 'dovecotpass';
CREATE USER IF NOT EXISTS 'postfix'@'%'      IDENTIFIED BY 'postfixpass';
CREATE USER IF NOT EXISTS 'roundcube'@'%'    IDENTIFIED BY 'roundcubepass';
CREATE USER IF NOT EXISTS 'accountadmin'@'%' IDENTIFIED BY 'accountadminpass';

-- ---- mail users table ----
USE mailserver;

CREATE TABLE IF NOT EXISTS virtual_users (
  id         INT          NOT NULL AUTO_INCREMENT,
  email      VARCHAR(255) NOT NULL,
  password   VARCHAR(255) NOT NULL COMMENT 'bcrypt hash ({BLF-CRYPT}$2a$...)',
  domain     VARCHAR(100) NOT NULL DEFAULT 'igsu.local',
  active     TINYINT(1)   NOT NULL DEFAULT 1,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_email (email)
) ENGINE=InnoDB;

-- ---- quarantine ----
CREATE TABLE IF NOT EXISTS quarantine_messages (
  id           INT           NOT NULL AUTO_INCREMENT,
  message_id   VARCHAR(512)  NOT NULL DEFAULT '',
  sender       VARCHAR(255)  NOT NULL,
  recipient    VARCHAR(255)  NOT NULL,
  subject      VARCHAR(1000) NOT NULL DEFAULT '',
  received_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  score        DECIMAL(5,2)  NOT NULL DEFAULT 0.00 COMMENT 'Ensemble score 0.00-1.00',
  verdict      ENUM('CLEAN','SPAM','QUARANTINE') NOT NULL DEFAULT 'QUARANTINE',
  sa_score     DECIMAL(5,1)  DEFAULT NULL COMMENT 'SpamAssassin raw score',
  llm_score    DECIMAL(5,2)  DEFAULT NULL COMMENT 'LLM spam probability',
  auth_score   DECIMAL(5,2)  DEFAULT NULL COMMENT 'Auth (DKIM+SPF) score',
  clamav_clean TINYINT(1)    DEFAULT NULL COMMENT '1=clean, 0=virus',
  clamav_virus VARCHAR(255)  DEFAULT NULL,
  adversarial  TINYINT(1)    NOT NULL DEFAULT 0,
  reasons      TEXT          COMMENT 'JSON array of scoring reasons',
  raw_headers  TEXT          COMMENT 'Email headers for review',
  body_preview VARCHAR(2000) DEFAULT NULL COMMENT 'First ~500 chars of body',
  raw_email    LONGBLOB      DEFAULT NULL COMMENT 'Full email for re-delivery on release',
  status       ENUM('pending','released','deleted') NOT NULL DEFAULT 'pending',
  reviewed_by  VARCHAR(255)  DEFAULT NULL,
  reviewed_at  TIMESTAMP     NULL DEFAULT NULL,
  PRIMARY KEY (id),
  INDEX idx_verdict    (verdict),
  INDEX idx_status     (status),
  INDEX idx_received   (received_at),
  INDEX idx_sender     (sender)
) ENGINE=InnoDB;

-- ---- scoring log (all emails, not just quarantined) ----
CREATE TABLE IF NOT EXISTS scoring_log (
  id           INT           NOT NULL AUTO_INCREMENT,
  message_id   VARCHAR(512)  NOT NULL DEFAULT '',
  sender       VARCHAR(255)  NOT NULL,
  recipient    VARCHAR(255)  NOT NULL,
  subject      VARCHAR(1000) NOT NULL DEFAULT '',
  scored_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  score        DECIMAL(5,2)  NOT NULL,
  verdict      ENUM('CLEAN','SPAM','QUARANTINE') NOT NULL,
  sa_score     DECIMAL(5,1)  DEFAULT NULL,
  llm_score    DECIMAL(5,2)  DEFAULT NULL,
  auth_score   DECIMAL(5,2)  DEFAULT NULL,
  reasons      TEXT,
  action_taken VARCHAR(50)   NOT NULL DEFAULT 'DUNNO' COMMENT 'Postfix action returned',
  PRIMARY KEY (id),
  INDEX idx_scored_at (scored_at),
  INDEX idx_verdict   (verdict)
) ENGINE=InnoDB;

-- ---- grants ----
GRANT SELECT ON mailserver.virtual_users TO 'dovecot'@'%';
GRANT SELECT ON mailserver.virtual_users TO 'postfix'@'%';
GRANT ALL    ON mailserver.virtual_users       TO 'accountadmin'@'%';
GRANT ALL    ON mailserver.quarantine_messages TO 'accountadmin'@'%';
GRANT ALL    ON mailserver.scoring_log         TO 'accountadmin'@'%';
GRANT ALL    ON roundcubemail.*                TO 'roundcube'@'%';

-- antispam policy service needs write access to quarantine + scoring
CREATE USER IF NOT EXISTS 'antispam'@'%' IDENTIFIED BY 'antispampass';
GRANT INSERT, SELECT ON mailserver.quarantine_messages TO 'antispam'@'%';
GRANT INSERT, SELECT ON mailserver.scoring_log         TO 'antispam'@'%';

FLUSH PRIVILEGES;
