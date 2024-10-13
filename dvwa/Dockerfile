FROM vulnerables/web-dvwa:latest
USER root  
RUN sed -i 's/stretch/buster/g' /etc/apt/sources.list
# Cài đặt Filebeat
RUN apt-get update && \
    apt-get install -y --allow-unauthenticated wget supervisor && \
    wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.15.0-amd64.deb && \
    dpkg -i filebeat-8.15.0-amd64.deb && \
    apt-get clean && \
    rm filebeat-8.15.0-amd64.deb
# Sao chép file cấu hình Supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Thiết lập Filebeat
COPY filebeat.yml /etc/filebeat/filebeat.yml
COPY modules.d/apache.yml /etc/filebeat/modules.d/apache.yml.disabled
RUN mv /etc/filebeat/modules.d/apache.yml.disabled /etc/filebeat/modules.d/apache.yml

# Quay lại user mặc định (nếu cần)
#USER www-data

# Khởi động cả Apache và Filebeat
COPY start.sh /start.sh
RUN chmod +x /start.sh
#CMD ["/start.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
