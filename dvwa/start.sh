#!/bin/bash

# Khởi động Apache
apache2-foreground &

# Khởi động Filebeat
filebeat -e -c /etc/filebeat/filebeat.yml 


