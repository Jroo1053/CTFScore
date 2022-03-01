"""
This file contains all of the routes associated with the api
"""

from json import JSONDecodeError
import orjson
from flask import current_app, Blueprint, jsonify, request
from flask.wrappers import Response

import datetime

from sqlalchemy import desc
from flask_login import current_user
import sqlalchemy
from sqlalchemy.sql import func

from Web import db
from .models import (IDSAlert, User, UserAlert, UserAsset, UserNetworkID,
                     UserStats, LogSource)
from Lib.models import DictObj
from Web.utils import api_is_auth
from Lib.scoring import alien_vault_USM_single
import logging
from Web import metrics

api = Blueprint("api", __name__, url_prefix="/api/")

logger = logging.getLogger(__name__)


"""
This format matches the one currently implemented by the log aggregator
"""
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"



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
    Simple endpoint to allow log aggregators to validate authentication
    before forwarding alerts
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
    Create a new IDS alerts from a list of alerts, designed to work
    with the log aggregator only but it could work with other stuff
    """
    full_request = orjson.loads(request.get_json())
    """
    Check if the current caller has a valid key an id pair, if not refuse
    connection
    """
    source_refresh_needed = True
    log_sources = db.session.query(LogSource).all()
    try:
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
                """
                Each alert is scored here and the result is tied to the alert
                itself so that the score can be displayed later.
                """
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
                    for x in log_sources:
                        if x.ids_name.lower() == alert["log_source"]["ids_name"].lower():
                            src_id = x.id
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
                UserAsset.user_id, IDSAlert.id
            ).order_by(
                desc(IDSAlert.id)
            ).limit(len(alerts_new)).all()

            user_alerts = []
            """
            Tie each alert to a user(s) if available, save result to UserAlert
            object
            """
            for alert in alerts_with_match:
                user_alerts.append(
                    UserAlert(
                        user_id=alert._data[0],
                        alert_id=alert._data[1]
                    )
                )
            db.session.bulk_save_objects(
                user_alerts
            )
            db.session.commit()
            stats = []
            """
            Update user statistics to reflect the changes made in the previous,
            ingest operations. 
            """
            for user in db.session.query(User).with_entities(
                User.id
            ).all():
                current_stats = db.session.query(
                    UserStats
                ).filter(
                    UserStats.user_id == user._data[0]
                ).first()
                updated_stats = db.session.query(
                    UserAlert, IDSAlert
                ).filter(
                    UserAlert.user_id == user._data[0]
                ).filter(
                    IDSAlert.id == UserAlert.alert_id
                ).with_entities(
                    func.count(UserAlert.user_id),
                    func.avg(IDSAlert.score),
                    func.min(IDSAlert.score),
                    func.max(IDSAlert.score),
                    func.sum(IDSAlert.score)
                ).all()
                current_stats.alert_count = updated_stats[0]._data[0]
                current_stats.alert_average = updated_stats[0]._data[1]
                current_stats.alert_min = updated_stats[0]._data[2]
                current_stats.alert_max = updated_stats[0]._data[3]
                current_stats.current_score = updated_stats[0]._data[4]
                stats.append(current_stats)
            db.session.add_all(stats)
            db.session.commit()
    except KeyError:
        logger.warning(
            "Received a malformed event forwading request from %s",
            request.remote_addr)
        return Response("", 400)
    except ValueError:
        return Response("", 400)
    except JSONDecodeError:
        return Response("", 400)
    return Response("", 200)


@ api.route("/events/<event_id>", methods=["GET"])
def get_retrive_alert(event_id):
    """
    Retrive a orjson representation of the alert specified by the event_id
    """
    alert = IDSAlert.query.all()
    if alert:
        return jsonify({
            "id": alert.id,
            "dest_ip": alert.dest_ip,
            "src_ip": alert.src_ip,
            "message": alert.message,
            "category": alert.category,
            "severity": alert.severity,
            "score": alert.score,
            "source": alert.ids_name,
            "timestamp": alert.timestamp
        })
    return Response("", 404)


@ api.route("/events/all/<id>", methods=["GET"])
def get_retrive_alerts(id):
    """
    Retrives orjson represnetations of all the alerts registered with the 
    system, for a specific user.
    Currently limited to 10,000 alerts to reduce load.
    """
    if not current_user.is_anonymous:
        if int(id) == current_user.id:
            alerts = db.session.query(
                IDSAlert
            ).filter(
                UserAlert.user_id == current_user.id
            ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).order_by(desc(IDSAlert.timestamp)).limit(10000).all()
            return jsonify(alerts)
        return Response("", 405)
    else:
        return Response("", 405)


@ api.route("/ids_events/<source>/<id>/<count>")
def get_retrive_alerts_by_source(id, source, count):
    """
    Get IDS alerts by user id, only from a certain source
    """
    if not current_user.is_anonymous:
        if int(id) == current_user.id:
            alerts = db.session.query(
                IDSAlert
            ).filter(
                func.lower(IDSAlert.ids_name) == func.lower(source)
            ).filter(
                UserAlert.user_id == current_user.id
            ).filter(
                UserAlert.alert_id == IDSAlert.id
            ).order_by(desc(IDSAlert.timestamp)).limit(count).all()
            if len(alerts) > 0:
                return jsonify(alerts)
        return Response("", 405)
    else:
        return Response("", 405)


@api.route("/score/<user_id>", methods=["GET"])
def get_user_stats(user_id):
    """
    Route to get the score associated with a specified user id, used to ajax
    the score on the index
    """
    if not current_user.is_anonymous:
        if int(user_id) == current_user.id:
            user_stats = UserStats.query.filter_by(
                user_id=current_user.id).first()
            if user_stats:
                try:
                    return jsonify({
                        "current_score": round(user_stats.current_score, 3),
                        "total_alerts": user_stats.alert_count,
                        "alert_average": round(user_stats.alert_average, 3),
                        "alert_max": user_stats.alert_max,
                        "alert_min": user_stats.alert_min
                    })
                except TypeError:
                    return Response("", 405)
    return Response("", 405)
