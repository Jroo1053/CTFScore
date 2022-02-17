from flask import current_app
from .models import UserAsset, User
from Web import login, db
from Lib.models import DictObj



def api_is_auth(api_key, api_id):
    """
    Util function to check wether an API request is valid and contains 
    the auth/id keys
    """
    valid_key_pairs = current_app.config['api_options'].key_pairs
    # TODO Fix
    for key_pair in valid_key_pairs:
        if api_id == key_pair.key_pair.id and\
                api_key == key_pair.key_pair.key:
            return True
    return False


@login.user_loader
def load_user(id):
    """
    Needed by the flask_login module
    """
    return User.query.get(int(id))


def get_user_id_from_alert(alert,user):
    user_assets = UserAsset.query.filter_by(id=user.id).all()
    for asset in user_assets:
        for ident in asset.network_identifiers:
            if alert.src_ip == ident.id_string:
                return user.id
    

def tie_alert_to_user(alert,users):
    user_ids = []
    user_assets = UserAsset.qeury.filter_by(
        id in user_ids
    )
    for user in users:
        id = get_user_id_from_alert(alert,user)
        if id:
            user_ids.append(id)
    return user_ids

def format_timestamp(timestamp=False):
    """
    Pretty print 'verbose' timestamps with jinja
    """
    format = "%d/%m/%Y %H:%M:%S"
    return timestamp.strftime(format)

current_app.jinja_env.filters["prettydate"] = format_timestamp
    