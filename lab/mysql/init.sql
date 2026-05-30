-- EcoVault database init
USE ecovault;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    api_key VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    stock INT DEFAULT 0
);

-- Transactions table
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    amount DECIMAL(10,2),
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Coupons table
CREATE TABLE coupons (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    discount_percent INT DEFAULT 10,
    used BOOLEAN DEFAULT FALSE,
    max_uses INT DEFAULT 1
);

-- Comments table (for stored XSS)
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed data
INSERT INTO users (email, password, role, api_key) VALUES
('admin@ecovault.com', 'SuperSecretAdmin123!', 'admin', 'flag{admin_api_key_4a7b9c}'),
('user@ecovault.com',  'User2026!',              'user',  NULL),
('alice@ecovault.com',  'AliceSpring2026!',       'user',  'flag{alice_api_key_2f8e1d}'),
('bob@ecovault.com',    'B0bTheBuilder!',          'user',  NULL),
('charlie@ecovault.com','Ch@rlieR0cks!',          'user',  NULL),
('eve@ecovault.com',    'Ev3TheSpy!',             'user',  'flag{eve_api_key_9c3b7a}');

INSERT INTO products (name, price, description, stock) VALUES
('EcoVault Premium',          99.99,  'Compte premium EcoVault',              100),
('Audit de sécurité API',     499.00, 'Audit complet des endpoints API',       50),
('VPN Corporate',             29.99,  'Abonnement VPN corporate mensuel',     200),
('Certificat SSL Wildcard',   199.99, 'Certificat SSL Wildcard 1 an',          75),
('Formation Sécu Interne',   1499.00, 'Formation sécurité pour employés',      30);

INSERT INTO coupons (code, discount_percent, max_uses) VALUES
('WELCOME10', 10, 1),
('SUMMER25',  25, 5),
('VIP50',     50, 1);

INSERT INTO comments (user_id, product_id, content) VALUES
(2, 1, 'Super produit, livraison rapide !'),
(3, 2, 'Audit très complet, je recommande.');
