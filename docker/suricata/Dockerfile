FROM jasonish/suricata:latest

USER root

VOLUME ["/var/log/suricata", "/etc/suricata/rules"]

CMD ["-r", "/pcaps/test.pcap", "--init-errors-fatal", "-v"]