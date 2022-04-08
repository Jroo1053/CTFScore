"""
Python implementations of several IDS alert prioritisation algorthims for use
in the Advanced CTF Scoring System and it's associated algorthim test suite
"""

import statistics
import numpy as np

def alien_vault_USM_single(alert, assets):
    for asset in assets:
        if alert["dest_ip"] in asset.asset.network_names:
            if alert['log_source']['ids_name'].lower() == "wazuh":
                scale = (0, alert["severity"], 15)
            elif alert['log_source']['ids_name'].lower() == "suricata":
                """
                Quick fix for me getting the suricata scales wrong. Also 1 is
                the most severe alert and not 3 so we've got to invert the result
                """
                score_fix = 2.0
                if alert["severity"] == 1:
                    score_fix = 3
                elif alert["severity"] == 3:
                    score_fix = 1
                
                scale = (0, score_fix, 3)
            scale = np.array(scale)
            """
            Normalise different IDS severity scales to 0-5
            """
            scale_min, scale_ptp = scale.min(), np.ptp(scale)
            normal_scale = ((scale - scale_min) / scale_ptp) * 5

            calculated_risk_value = (asset.asset.value *
                                     normal_scale[1] * alert['log_source']['reliability']) / 25
            return round(calculated_risk_value,2), round(normal_scale[1],2)
    return 0, 0


def naive_algor(alerts):
    # Get average event severity
    alert_severities = []
    alert_count = 0
    for source in alerts:
        if alerts:
            for alert in source:
                if hasattr(alert, "severity"):
                    alert_severities.append(alert.severity)
                    alert_count += 1
    print("(Naive) Average Alert Severity: ",
          statistics.mean(alert_severities))
    print("(Naive) Total Score: ",
          (statistics.mean(alert_severities) * alert_count))
    print("(Naive) Number of Valid Alerts:", len(alert_severities))
