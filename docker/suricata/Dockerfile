FROM jasonish/suricata:latest

USER root

COPY suricata.yaml /etc/suricata/suricata.yaml

VOLUME ["/var/log/suricata", "/etc/suricata/rules"]

CMD ["-r", "/pcaps/test.pcap", "-c", "/etc/suricata/suricata.yaml", "-l", "/var/log/suricata", "-v"]