from flask_login.mixins import UserMixin
from Web import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dataclasses import dataclass

@dataclass
class IDSAlert(db.Model):
    """
    Class to represent IDS alerts in the DB
    """
    id: int
    dest_ip: str
    src_ip: str
    message: str
    timestamp: str
    severity: int
    ids_name: str
    category: str
    score: float
    normalised_severity: float


    id = db.Column(db.Integer, primary_key=True)
    dest_ip = db.Column(db.String(120))
    src_ip = db.Column(db.String(120))
    message = db.Column(db.String(120))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    severity = db.Column(db.Integer)
    ids_name = db.Column(db.String(120))
    category = db.Column(db.String(120))
    """
    Score associated with each alert should always be calculated using one of
    the algorithms available in Lib.scoring
    """
    score = db.Column(db.Float)
    """
    The severity of this alert when rescaled to fit the range used in the
    scoring algorithm
    """
    normalised_severity = db.Column(db.Float())
    log_source = db.Column(db.Integer, db.ForeignKey("log_source.id"))
    user_alert = db.relationship("UserAlert", backref="idsalert",
    lazy="dynamic")


class User(UserMixin, db.Model):
    """
    Class to represent user accounts in the database
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    access_token = db.Column(db.String(128))
    registered_assets = db.relationship("UserAsset", backref="userasset",
                                        lazy="dynamic")
    ids_alerts = db.relationship("UserAlert", backref="user", lazy="dynamic")


    def set_access_token(self, token):
        self.access_token = generate_password_hash(token)

    def check_access_token(self, unverified_token):
        return check_password_hash(self.access_token, unverified_token)

class UserAlert(db.Model):
    """
    Instead of tying IDSAlert directly to users we, tie alerts
    to users via this class. This allows us to tie an alerts to N users 
    """
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey("user.id"))
    alert_id = db.Column(db.Integer,db.ForeignKey("ids_alert.id"))

class TargetAsset(db.Model):
    """
    Used to represent the vulnerable nodes in the CTF.
    """
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    value = db.Column(db.Integer)
    network_identifiers = db.relationship(
        "TargetNetworkID")


class TargetNetworkID(db.Model):
    """
    Used to represent the network IDs asscoated with a target node.
    can be hostname or IP but, should match the ID used with attached IDS. 
    """
    id = db.Column(db.Integer, primary_key=True)
    id_string = db.Column(db.String(128))
    node_id = db.Column(db.Integer, db.ForeignKey("target_asset.id"))


class UserAsset(db.Model):
    """
    Represents an asset under the control of the CTF partipcent. Needed to 
    tie individual IDS alerts to specific users. Created during registration,
    but can also be set ahead of time via the mandatory assets field which, is
    required to ingest HIDS alerts that do not contain a source ip. 
    """
    id = db.Column(db.Integer, primary_key=True)
    network_identifiers = db.relationship("UserNetworkID")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class UserNetworkID(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_string = db.Column(db.String(128))
    node_id = db.Column(db.Integer, db.ForeignKey("user_asset.id"))

class LogSource(db.Model):
    """DB representation of the log sources as defined by connected aggregators """
    id = db.Column(db.Integer, primary_key=True)
    ids_name = db.Column(db.String(128),unique=True)
    reliability = db.Column(db.Integer)
    alerts = db.relationship("IDSAlert")

class UserStats(db.Model):
    """
    Representation of the stats tied to each user. Multiple UserStats objects
    can be tied to a user to allow stats to be tracked over time.
    """
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey("user.id"))
    current_score = db.Column(db.Float)
    alert_count = db.Column(db.Integer)
    alert_average = db.Column(db.Float)
    alert_max = db.Column(db.Float)
    alert_min = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow())

class IDSStats(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    ids_name = db.Column(db.String)
    total_alerts = db.Column(db.Integer)
    user_id = db.Column(db.Integer,db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow())