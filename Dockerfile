FROM php:8.2-apache

# Enable mod_rewrite for routing
RUN a2enmod rewrite

# Install MySQL PDO driver
RUN docker-php-ext-install pdo pdo_mysql
