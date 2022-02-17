"""
Python implementations of several IDS alert prioritisation algorthims for use
in the Advanced CTF Scoring System and it's associated algorthim test suite
"""

import imp
from locale import normalize
from os import stat
import statistics
from time import process_time
import numpy as np


import sklearn
from sklearn import preprocessing


def alien_vault_USM_algor(alerts, assets):
    """
    Applies the formula used by alienvault/hp OSSIM SIEM as described by
    (Renners, 2019). This is a straight-forward formula however, a lot of work
    is required to produce the initial values.
    """
    from sklearn.preprocessing import minmax_scale

    risk_values = []
    alert_count = 0
    for alert in alerts:
        for asset in assets:
            if alert.dest_ip in asset.asset.network_names:
                """
                Normalise different IDS severity scales to 0-5
                """
                if alert.ids_name.lower() == "wazuh":
                    scale = (0, alerts.severity, 16)
                elif alert.ids_name.lower() == "suricata":
                    scale = (0, alert.severity, 7)
                normal_scale = preprocessing.minmax_scale(scale, (0, 5))
                calculated_risk_value = (asset.asset.value *
                                         normal_scale[2] * 8) / 25
                risk_values.append(calculated_risk_value)
                alert_count += 1
    return risk_values


def alien_vault_USM_single(alert, assets):
    for asset in assets:
        if alert.dest_ip in asset.asset.network_names:
            if alert.log_source.ids_name.lower() == "wazuh":
                scale = (0, alert.severity, 16)
            elif alert.log_source.ids_name.lower() == "suricata":
                scale = (0, alert.severity, 7)
            #normal_scale = preprocessing.minmax_scale(scale, (0, 5))
            scale = np.array(scale)
            """
            scale_min,scale_max = scale.min(), scale.max()
            normal_scale = (scale - scale_min) / (scale_max - scale_min) 
            """
            scale_min, scale_ptp = scale.min(), np.ptp(scale)
            normal_scale = ((scale - scale_min) / scale_ptp) * 5
            """
            TODO Normalise different IDS severity scales to 0-5
            """
            calculated_risk_value = (asset.asset.value *
                                     normal_scale[1] * alert.log_source.reliability) / 25
            return calculated_risk_value, normal_scale[1]
    return 0, 0


def micro_focus_arc_sight_algor(alerts, assets):
    """
    Applies the formula used in Micro sights' USM as described by 
    (Renners, 2019)(Thiele, n.d.). More complex than other options but more 
    comprehensive

    priority = agent_severity * relevance / ((relevance + model_confidence) - relevance *
                                             model_confidence / 10) * (1 + severity * 3 / 100) * (1 + criticality - 8 / 10 * 0.2)
    """

    pass


def alsubhi_algor():
    """
    Applies the formula as described by (Alsubhi et al., 2008)
    """
    pass


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


def original_algor(alerts, assets):
    pass
