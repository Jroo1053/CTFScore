# pylint: disable=import-error,pointless-string-statement
"""
This file contains all of the routes associated with the api this includes:
1. The route used to ingest all alerts
2. All the routes associated used for AJAX
3. Some utility routes
"""

import statistics
import operator
import datetime
import logging
from sqlalchemy.sql import func
from sqlalchemy import desc
import orjson
from flask import current_app, Blueprint, jsonify, request
from flask.wrappers import Response

from flask_login import current_user

from Lib.scoring import alien_vault_USM_single
from Web import db
from Web.utils import api_is_auth

from .models import (IDSAlert, IDSStats, UserAlert, UserAsset, UserNetworkID,
                     UserStats, LogSource)


api = Blueprint("api", __name__, url_prefix="/api/")

logger = logging.getLogger(__name__)


"""
This format matches the one currently implemented by the log aggregator
"""
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


"""
Quick fix for preventing IDS alerts from the system itself from being ingested
. In the future this, should be configured from config.yml. The below messages
will remain default however.
"""
FILTERED_MESSAGES = [
    "Docker: Error message", "Interface entered in promiscuous(sniffing) mode."
]


@api.route("/status", methods=["GET"])
def api_get_status():
    """
    Simple endpoint to return the status of the api,
    of course if we get here it should only ever be working, right?
    """
    return jsonify({"Received": "True"})


@api.route("/verifyauth", methods=["POST"])
def post_verify_auth():
    """
    _summary_: Simple endpoint to allow log aggregators to validate authentication
    before forwarding alerts
    Returns:
        dict: json success message or 500 on failure
    """
    request_json = orjson.loads(request.get_json())
    try:
        if not api_is_auth(request_json["key"], request_json["id"]):
            logger.info("Rejected auth verification request from %s",
                        request.remote_addr)
            return Response("", 403)
    except KeyError:
        return Response("", 400)
    logger.info("Accepted auth verification request from %s",
                request.remote_addr)
    return Response("", 200)


@api.route("/events", methods=["POST"])
def post_create_ids_alerts():
    """
    _summary_:  Primary API route used to ingest all alerts from attached
                log aggregators. Alerts are initally proccessed,scored and stored
                as IDSAlert before being bound to users via UserAlert Objects
    Returns:
        dict: json success message or 500 on failure
    """
    full_request = orjson.loads(request.get_json())
    source_refresh_needed = True
    log_sources = db.session.query(LogSource).all()
    try:
        # Check if the caller is authorized if not return
        if not api_is_auth(full_request["key"], full_request["id"]):
            logger.warning(
                "%s Attempted to forward new alerts but, could not verify",
                request.remote_addr)
            return Response("", 403)
    except KeyError:
        logger.warning(
            "%s Attempted to forward new alerts but, sent a malformed request ",
            request.remote_addr)
        return Response("", 400)
    try:
        alerts_raw = orjson.loads(full_request["request_content"])
        alerts_new = []
        for source in alerts_raw:
            for alert in source:
                if source_refresh_needed:
                    log_sources = db.session.query(
                        LogSource).all()
                    source_refresh_needed = False
                if alert:
                    """
                    Create a log source entry if, this alert originates from a
                    source that hasn't been ingested yet
                    """
                    sources = [x.ids_name.lower() for x in log_sources]
                    if not alert["log_source"]["ids_name"].lower() in sources:
                        log_source = LogSource(
                            ids_name=alert["log_source"]["ids_name"],
                            reliability=alert["log_source"]["reliability"]
                        )
                        db.session.add(log_source)
                        db.session.commit()
                        source_refresh_needed = True
                    alert_score, normalised_severity = alien_vault_USM_single(
                        alert,
                        current_app.config['api_options'].registered_assets)
                    """
                    Save the alert to the database but, do not tie it to a
                    user at this stage
                    """
                    for active_source in log_sources:
                        if active_source.ids_name.lower()\
                            == alert["log_source"]["ids_name"].lower()\
                                and alert_score > 0 and not alert["message"]\
                                in FILTERED_MESSAGES:
                            src_id = active_source.id
                            db_alert = IDSAlert(
                                dest_ip=alert["dest_ip"],
                                src_ip=alert["src_ip"],
                                message=alert["message"],
                                timestamp=datetime.datetime.strptime(alert["timestamp"],
                                                                     TIME_FORMAT),
                                severity=alert["severity"],
                                category=alert["category"],
                                ids_name=alert["log_source"]["ids_name"],
                                score=alert_score,
                                normalised_severity=normalised_severity,
                                log_source=src_id)
                            alerts_new.append(db_alert)
            db.session.bulk_save_objects(
                alerts_new
            )
            db.session.commit()
            logger.info("Ingested %d Alerts From %s", len(alerts_new), source)
            """
            Tie each alert to user(s) by matching assets
            """
            alerts_with_match = db.session.query(
                IDSAlert, UserNetworkID
            ).filter(
                IDSAlert.src_ip == UserNetworkID.id_string
            ).filter(
                UserNetworkID.node_id == UserAsset.id
            ).with_entities(
                UserAsset.user_id,
                IDSAlert.id,
                IDSAlert.message,
                IDSAlert.ids_name,
                IDSAlert.dest_ip,
                IDSAlert.timestamp,
                IDSAlert.score
            ).order_by(
                desc(IDSAlert.id)
            ).limit(len(alerts_new)).all()
            db.session.bulk_save_objects(
                [
                    UserAlert(user_id=alert[0], alert_id=alert[1]) for alert in alerts_with_match
                ]
            )
            db.session.commit()
            """
            Tie each alert to a user(s) if available, save result to UserAlert
            object
            """
            stats = []
            """
            Update user statistics to reflect the changes made in the previous,
            ingest operations.
            """
            latest_alert__scores = db.session.query(IDSAlert.score, UserAlert.user_id
                                                    ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).group_by(IDSAlert.timestamp, IDSAlert.message, UserAlert.user_id).all()

            alert_users = set([x[0] for x in alerts_with_match])
            for user in alert_users:
                ingest_time = datetime.datetime.utcnow()
                user_scores = [y[0]
                               for y in latest_alert__scores if y[1] == user]
                if len(user_scores) > 0:
                    new_stats = UserStats(
                        user_id=user,
                        alert_count=len(user_scores),
                        alert_average=statistics.mean(user_scores),
                        alert_min=min(user_scores),
                        alert_max=max(user_scores),
                        current_score=sum(user_scores),
                        timestamp=ingest_time
                    )
                    stats.append(new_stats)
        db.session.bulk_save_objects(
            stats
        )
        db.session.commit()
        return jsonify({
            "Received": True
        })
    except KeyError as key_err:
        logger.warning(
            "Received a malformed event forwading request from %s",
            request.remote_addr)
        logger.warning(
            str(key_err)
        )
        return Response("", 500)
    except ValueError as val_err:
        logger.warning(
            "Received a malformed event forwading request from %s",
            request.remote_addr)
        logger.warning(
            str(val_err)
        )
        return Response("", 500)
    except Exception as general_expect:
        logger.error(str(general_expect))
        return Response("", 500)


@api.route("/events/all/<user_id>", methods=["GET"])
def get_retrive_alerts(user_id):
    """
    _summary_: Retrive a list of all IDS alerts for a certian user.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            alerts = db.session.query(
                IDSAlert
            ).filter(
                UserAlert.user_id == current_user.id
            ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).order_by(desc(IDSAlert.timestamp)).group_by(IDSAlert.timestamp).limit(10000).all()
            return jsonify(alerts)
        return Response("", 405)
    return Response("", 405)


@api.route("/ids_events/<source>/<user_id>/<count>")
def get_retrive_alerts_by_source(user_id, source, count):
    """
    _summary_: Retrive a list of all IDS alerts by user for a specified source.
    Args:
        user_id (str): id of user to filter by.
        source (str) : source IDS (case insensitive).
        count (str): number of alerts to retrive.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            alerts = db.session.query(
                IDSAlert
            ).filter(
                func.lower(IDSAlert.ids_name) == func.lower(source)
            ).filter(
                UserAlert.user_id == current_user.id
            ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).group_by(
                IDSAlert.timestamp).order_by(desc(IDSAlert.timestamp)).limit(count).all()
            if len(alerts) > 0:
                return jsonify(alerts)
        return Response("", 405)
    return Response("", 405)


@ api.route("/cats/<user_id>")
def get_ids_cats(user_id):
    """
    _summary_: Retrive a list of the most common IDS alert categories.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        per_cat_count = []
        if int(user_id) == current_user.id:
            distinct_stats = db.session.query(IDSAlert.message, IDSAlert.timestamp,
                                              IDSAlert.category, IDSAlert.ids_name
                                              ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).filter(
                UserAlert.user_id == user_id
            ).group_by(IDSAlert.timestamp, IDSAlert.message).all()

            for stat in set([x[2:4] for x in distinct_stats]):
                if len(stat[0]) > 0:
                    per_cat_count.append({
                        "category": stat[0] + " (" + stat[1] + ")",
                        "count":   len([y[2] for y in distinct_stats if y[2] == stat[0]])
                    })
                else:
                    per_cat_count.append({
                        "category": "No Category" + " (" + stat[1] + ")",
                        "count":   len([y[2] for y in distinct_stats if y[2] == stat[0]])
                    })

        return jsonify(per_cat_count)
    return Response("", 400)


@ api.route("/score/<user_id>", methods=["GET"])
def get_user_stats(user_id):
    """
    _summary_: Retrive the users current score + current stats. Used for
    main index display.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            user_stats = UserStats.query.filter_by(
                user_id=current_user.id).order_by(
                    desc(UserStats.timestamp)
            ).first()
            if user_stats:
                try:
                    return jsonify({
                        "current_score": round(user_stats.current_score, 3),
                        "total_alerts": user_stats.alert_count,
                        "alert_average": round(user_stats.alert_average, 3),
                        "alert_max": user_stats.alert_max,
                        "alert_min": user_stats.alert_min
                    })
                except TypeError as type_fail:
                    logger.error(
                        "Failed to generate stats for %s with message: %s",
                        current_user.id, str(type_fail))
                    return Response("", 405)
    return Response("", 405)


@ api.route("/ids/stats/<user_id>", methods=["GET"])
def get_ids_stats(user_id):
    """
    _summary_: Retrive the current stats for each IDS. Filtered by
    the specified user.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            merged_stats = []
            distinct_stats = db.session.query(IDSAlert.message,
                                              IDSAlert.timestamp, IDSAlert.ids_name,
                                              IDSAlert.score,
                                              ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).filter(
                UserAlert.user_id == user_id
            ).group_by(IDSAlert.timestamp, IDSAlert.message, IDSAlert.ids_name).all()
            alert_sources = set([x[2] for x in distinct_stats])
            for ids in alert_sources:
                alert_scores = [x[3]
                                for x in distinct_stats if x[2] == ids]
                stat = {
                    "ids_name": ids,
                    "alert_count": len(alert_scores),
                    "alert_avg": round(statistics.mean(alert_scores), 2),
                    "alert_max": max(alert_scores),
                    "alert_min": min(alert_scores),
                    "total_score": round(sum(alert_scores), 2)
                }
                merged_stats.append(stat)
            return jsonify(merged_stats)
    return Response("", 400)


@ api.route("/score/time/<user_id>", methods=["GET"])
def get_score_with_time(user_id):
    """
    _summary_: Retrives all stats for the specified user over the
     total duration of the CTF.

    TODO: Fully Implement per IDS stats.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            timed_scores = db.session.query(
                UserStats
            ).filter(
                UserStats.user_id == user_id
            ).with_entities(
                UserStats.current_score,
                UserStats.timestamp,
                UserStats.alert_count
            ).limit(5000).all()
            ids_totals = db.session.query(
                IDSStats
            ).filter(
                IDSStats.user_id == user_id
            ).all()
            scores = []
            for score in range(0, len(timed_scores)):
                final_json = {
                    "score": timed_scores[score][0],
                    "timestamp": timed_scores[score][1],
                    "total_alerts": timed_scores[score][2],
                    "ids_stats": []
                }
                for stat in ids_totals:
                    if stat.timestamp == timed_scores[score][1]:
                        final_json["ids_stats"].append({
                            "ids_name": stat.ids_name.lower(),
                            "total_alerts": stat.total_alerts
                        })
                scores.append(final_json)
            return jsonify(scores)
    return Response("", 400)


@ api.route("/score/severities/<user_id>", methods=["GET"])
def get_alert_severities(user_id):
    """
    _summary_: Retrives list of the most common alert severity levels, filtered,
    by user and grouped by IDS.
    TODO: Handle IDS that use inverted scales.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            distinct_stats = db.session.query(IDSAlert.message,
                                              IDSAlert.timestamp,
                                              IDSAlert.ids_name,
                                              IDSAlert.severity
                                              ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).filter(
                UserAlert.user_id == user_id
            ).group_by(IDSAlert.timestamp, IDSAlert.message, IDSAlert.severity).all()
            final_json = []
            for level in set([x[2:4] for x in distinct_stats]):
                final_json.append({
                    "severity": level[1],
                    "source": level[0],
                    "count": len([y[3] for y in distinct_stats if y[3] == level[1]]),
                })
            return jsonify(final_json)
    return Response("", 400)


@ api.route("/score/category/<user_id>", methods=["GET"])
def get_score_categoires(user_id):
    """
    _summary_: Retrives count of alert category filtered by user
    and grouped by IDS.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            categories = db.session.query(
                IDSAlert
            ).filter(
                UserAlert.user_id == user_id
            ).filter(
                IDSAlert.id == UserAlert.alert_id
            ).with_entities(
                IDSAlert.ids_name,
                IDSAlert.category,
                func.count(IDSAlert.category),
            ).group_by(
                IDSAlert.category
            ).all()
            final_json = []
            for cat in categories:
                if len(cat[1]) > 0:
                    final_json.append(
                        {
                            "source": cat[0],
                            "category": cat[1],
                            "occurrences": cat[2]
                        }
                    )
                else:
                    final_json.append(
                        {
                            "source": cat[0],
                            "category": "No category",
                            "occurrences": cat[2]
                        }
                    )
            return jsonify(final_json)
    return Response("", 400)


@ api.route("/score/message/<user_id>", methods=["GET"])
def get_alert_messages(user_id):
    """
    _summary_: Retrives the five most common IDS alert messages
    and impact on score. Filtered by user like all API calls.
    Args:
        user_id (str): id of user to filter by.
    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            final_json = []
            distinct_stats = db.session.query(IDSAlert.message,
                                              IDSAlert.ids_name
                                              ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).filter(
                UserAlert.user_id == user_id
            ).group_by(IDSAlert.timestamp, IDSAlert.message).all()
            alert_messages = set([x[0:2] for x in distinct_stats])
            for message in alert_messages:
                final_json.append({
                    "source": message[1],
                    "message": message[0],
                    "count": len(list([y[0] for y in distinct_stats if y[0] == message[0]]))
                }
                )
            if len(final_json) > 0:
                final_json.sort(key=operator.itemgetter("count"))
                return jsonify(final_json[-5:])
    return Response("", 400)


@api.route("/alert/<alert_id>/stats/<user_id>")
def get_alert_stats(alert_id, user_id):
    """
    _summary_: Gets statistics on an individual alert including; total ourcances
    and impact on score. Filtered by user like all API calls.
    Args:
        alert_id (str): id of the IDSAlert Object to read.
        user_id (str): id of user to filter by.

    Returns:
        dict: 'jsonified' dict of stats.
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            selected_alert = db.session.query(
                IDSAlert
            ).filter(
                IDSAlert.id == alert_id
            ).first()
            if selected_alert:
                selected_alert_stats = db.session.query(
                    UserAlert
                ).filter(
                    UserAlert.user_id == user_id
                ).filter(
                    UserAlert.alert_id == IDSAlert.id
                ).filter(
                    IDSAlert.message == selected_alert.message,
                    IDSAlert.dest_ip == selected_alert.dest_ip
                ).group_by(
                    IDSAlert.timestamp, IDSAlert.message
                ).with_entities(
                    IDSAlert.timestamp,
                    IDSAlert.score
                ).all()
                current_stats = db.session.query(
                    UserStats
                ).filter(
                    UserStats.user_id == user_id
                ).order_by(
                    desc(UserStats.timestamp)
                ).first()
                scores = [x[1] for x in selected_alert_stats]
                score_percentage = (
                    sum(scores) / current_stats.current_score) * 100
                return jsonify({
                    "last_occurrence": selected_alert_stats[-1][0],
                    "first_occurrence": selected_alert_stats[0][0],
                    "total_occurrences": len(selected_alert_stats),
                    "total_score": sum(scores),
                    "score_percentage": ("({}%)".format(round(score_percentage, 2)))
                })
    return Response("", 400)
