# pylint: disable=import-error,pointless-string-statement
"""
This file contains all of the routes used by the UI
"""
import secrets
from Web import db
from .models import (
    LogSource, TargetAsset, TargetNetworkID, UserAsset, IDSAlert,
    UserNetworkID, User, UserStats)
from .forms import ConfigureForm, LoginForm, RegistrationForm
from flask_login import current_user, logout_user
from flask_login.utils import login_required, login_user

from Web import db
from flask import (current_app, Blueprint, render_template, jsonify,
                   request, url_for, redirect, flash)
from werkzeug.urls import url_parse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func
import logging

ui = Blueprint("ui", __name__, url_prefix="/")

logger = logging.getLogger(__name__)

"""
Contingency for changing the name of the system as (ACSS) it's really not great
right now
"""
BASE_DOC_TITLE = " CTFScore"


@ui.route("/")
@ui.route("/index")
@login_required
def index():
    """
    Route for the index / home page, currently the main source of info on
    alerts and scoring
    """
    title = "Home |" + BASE_DOC_TITLE
    triggered_ids = ["Wazuh", "Suricata"]

    return render_template("index.html", total_score=0, total_alerts=0,
                           average_alert=0, highest_alert=0, lowest_alert=0,
                           title=title, request=request, active_ids=triggered_ids)


@ui.route("/alerts")
@login_required
def alerts():
    """
    Route for the alerts history page, that displays a summary of all of the
    recorded IDS alerts and provides a jumping off point for the scoring
    breakdown
    """
    title = "Alerts |" + BASE_DOC_TITLE
    return render_template("alerts.html", title=title)


@ui.route("/configure", methods=[])
@login_required
def configure():
    """
    Route for the account configuration page, used to update the assets,
    currently not, reachable from the system itself
    """
    title = "Configure |" + BASE_DOC_TITLE
    configure_form = ConfigureForm()
    if configure_form.validate_on_submit:
        if configure_form.append_field.data:
            configure_form.registered_assets.append_entry()
            return render_template("configure.html", form=configure_form)
        if configure_form.submit.data:
            try:
                for asset in configure_form.registered_assets.data:
                    if asset:
                        user_asset = UserAsset(
                            user_id=current_user.id
                        )
                        db.session.add(user_asset)
                        db.session.commit()
                        user_asset_id = UserNetworkID(
                            id_string=asset,
                            node_id=user_asset.id
                        )
                        db.session.add(user_asset_id)
                db.session.commit()
                return render_template("configure.html",
                                       form=configure_form, title=title)
            except IntegrityError:
                flash("That username is already taken")
                return render_template("register.html", form=reg_form,
                                       title=title)
    return render_template("configure.html", form=configure_form, title=title)


@ui.route("/alert/<alert_id>")
@login_required
def alert(alert_id):
    """
    Route for the alert/scoring breakdown, this page is used to present
    the scoring algorithm in detail and provide a breakdown for every score
    on a per alert basis
    """
    title = "Alert Breakdown |" + BASE_DOC_TITLE
    breakdown_alert = IDSAlert.query.filter_by(id=alert_id).first()
    breakdown_net_id = db.session.query(
        TargetNetworkID
    ).filter(
        TargetNetworkID.id_string == breakdown_alert.dest_ip
    ).first()
    breakdown_asset = db.session.query(
        TargetAsset
    ).filter(
        TargetAsset.id == breakdown_net_id.node_id
    ).first()
    breakdown_source = db.session.query(
        LogSource
    ).filter(
        LogSource.id == breakdown_alert.log_source
    ).first()
    return render_template("scoring_breakdown.html",
                           alert=breakdown_alert, title=title,
                           asset=breakdown_asset, source=breakdown_source)


@ui.route("/register", methods=["GET", "POST"])
def register():
    """
    Route used for making initial contact with unknown nodes and registering
    users with the password-less authentication system. Users are identified
    by an randomly generated access token and a username
    """
    title = "Register |" + BASE_DOC_TITLE
    user_ip = request.remote_addr
    if current_user.is_authenticated:
        return redirect(url_for("ui.index"))
    reg_form = RegistrationForm()

    if reg_form.validate_on_submit() and reg_form.submit.data:
        if len(reg_form.registered_assets.data) != len(set(reg_form.registered_assets.data)):
            flash("Assets Must Be Unique")
            return redirect(url_for("ui.register"))
        try:
            new_user = User(
                username=reg_form.username.data)
            new_token = secrets.token_urlsafe(128)
            new_user.set_access_token(new_token)
            db.session.add(new_user)
            db.session.commit()
            new_stats = UserStats(
                user_id=new_user.id,
                current_score=0,
                alert_count=0
            )
            db.session.add(new_stats)
            db.session.commit()
        except IntegrityError as int_error:
            logger.error(str(int_error))
            flash("That username is already taken")
            return redirect(url_for("ui.register"))
        try:
            for asset in reg_form.registered_assets.data:
                if asset:
                    user_asset = UserAsset(
                        user_id=new_user.id
                    )
                    db.session.add(user_asset)
                    db.session.commit()
                    user_asset_id = UserNetworkID(
                        id_string=asset,
                        node_id=user_asset.id
                    )
                    db.session.add(user_asset_id)
            db.session.commit()
            for asset in current_app.config['api_options'].mandatory_assets:
                if asset:
                    mandatory_asset = UserAsset(
                        user_id=new_user.id,
                    )
                    db.session.add(mandatory_asset)
                    db.session.commit()
                    for network_id in asset.asset.network_names:
                        if network_id:
                            mandatory_asset_id = UserNetworkID(
                                id_string=network_id,
                                node_id=mandatory_asset.id
                            )
                            db.session.add(mandatory_asset_id)
                            db.session.commit()
            return render_template("register.html", new_token=new_token,
                                   form=reg_form, title=title, user_ip=user_ip)
        except Exception as e:
            logger.error(str(int_error))
            flash("That username is already taken")
            return render_template("register.html", form=reg_form, title=title,
                                   user_ip=user_ip)
    return render_template("register.html", form=reg_form, title=title,
                           user_ip=user_ip)


@ui.route("/login", methods=["GET", "POST"])
def login():
    """
    Page used to login users with, the key and username assigned in, the
    register page.
    """
    title = "Login |" + BASE_DOC_TITLE
    if current_user.is_authenticated:
        return redirect(url_for('ui.index'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(username=login_form.username.data).first()
        if user is None or\
                not user.check_access_token(login_form.access_token.data):
            flash('Invalid username or password')
            return redirect(url_for('ui.login'))
        login_user(user, remember=login_form.remember_me.data)
        """
        Check if this request was the result of a redirect
        """
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("ui.index")
        return redirect(next_page)
    return render_template('login.html', form=login_form, title=title)


@login_required
@ui.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Forgot to implement this before testing the login function whoops!
    There isn't a log out page in itself but there are links to the right
    url in the navigation
    """
    logout_user()
    return redirect(url_for('ui.index'))
