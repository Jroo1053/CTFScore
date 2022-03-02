# Advanced CTF Scoring System \ CTFScore IDS JSON Format Table

The below table is a continously(mabye) updated list of each of the JSON pointers to use when parsing alerts from one of the IDS supported by CTFScore. These pointers will need to be fed into the system via the log aggregator config file

| IDS | Type |  Format| Timestamp Field | Source IP Field  | Dest IP Field | Alert Description Field | Severity Field | Sample File |
|-----|------|--------|-----------------|------------------|---------------|-------------------------|----------------|-------------|
| Suricata | NIDS | [JSON / Lua / HTTP / Syslog](https://suricata.readthedocs.io/en/suricata-6.0.3/output/index.html)| timestamp (YYYY-MM-DDT)  | /src_ip | /dest_ip | /alert/signature | alert/severity/ 1-3* | [Sample](https://suricata.readthedocs.io/en/suricata-6.0.3/output/eve/eve-json-format.html)
| OSSEC  | HIDS | [JSON / Syslog / Database / Email ](https://www.ossec.net/docs/docs/manual/output/index.html)  | /timestamp (Unix Epoch) | /data/srcip | /agent/name | /rule/description | /rule/level (0-15)
| teler | HIDS |  [JSON](https://www.notion.so/Usage-e57c5e386a264c68b5c970eba003c303) | /time_local  (DD/MM/YY:HH:MM:SS) | /remote_addr | /request_uri | /category | None 
| Wazuh | HIDS | [Plain / JSON](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/logging.html) | /rule/timestamp (Unix Epoch) | /data/srcip | /agent/name| /rule/description | /rule/level (0-15)
| Zeek | NIDS | [JSON / TSV]() | ts (Unix Epoch) | /id.orig_h | /id.resp_h | service / origin file | none | [Sample](https://docs.zeek.org/en/master/logs/index.html)
| SLIPS | NIDS | [JSON / TSV]() |

\*3 is this the least important alert
