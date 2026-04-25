# web/Dockerfile
# Using a Debian-based PHP-Apache image
FROM php:8.3-apache-bookworm



# If you need to install more system packages (e.g., git, zip, unzip)
RUN apt-get update && apt-get install -y \
     git \
     zip \
     unzip \
     && rm -rf /var/lib/apt/lists/*


COPY server.crt /etc/apache2/ssl/server.crt
COPY server.key /etc/apache2/ssl/server.key

COPY sbosecure.conf /etc/apache2/sites-available/sbosecure.conf

RUN a2enmod ssl 


RUN a2enmod rewrite

RUN a2ensite sbosecure

EXPOSE 80
EXPOSE 443

