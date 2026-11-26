[suricata.yaml.diff.md](https://github.com/user-attachments/files/35478676/suricata.yaml.diff.md)
# Perubahan suricata.yaml

Lokasi: /etc/suricata/suricata.yaml

```yaml
HOME_NET: "[10.10.10.0/24]"

af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

rule-files:
  - suricata.rules
  - local.rules
```
