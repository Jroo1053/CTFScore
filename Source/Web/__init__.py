"""

    Advanced CTF Scoring System - API/Web UI
    Copyright (C) 2021  Joseph Frary

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""

"""
Setup flask app and related dependencies according to the config file
"""


from argparse import ArgumentParser
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
from Lib.utils import get_config_opts
from Lib.models import DictObj
import logging
import sys
from flask_migrate import Migrate
from flask_login import LoginManager
from .error_handlers import register_error_handlers
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import sqlalchemy
from prometheus_flask_exporter import PrometheusMetrics

parser = ArgumentParser(
    description="Advanced CTF Scoring System - Web UI/ Api")
parser.add_argument("-c", "--config-file", dest="config_file_path",
                    help="Select location of config file", metavar="FILE")
parser.add_argument("-v", "--verbose", dest="is_verbose",
                    help="Verbose Output", action="store_true")
parser.set_defaults(is_verbose=False)

try:
    logging.basicConfig(
        filename="/var/log/ctfweb/web.log",
        level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
except FileNotFoundError:
    logging.basicConfig(
        filename="web.log",
        level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
"""
It appears that flask migrate doesn't work with apps that takes command line
args, unless we do this.
"""
args, _ = parser.parse_known_args()

"""
Launch global libraries
"""

db = SQLAlchemy(session_options={
    'expire_on_commit':False
})
migrate = Migrate(db)
login = LoginManager()
metrics = PrometheusMetrics.for_app_factory()


DEFAULT_CONFIG_PATH = "./etc/ctfscore/config.yml"



def create_app(args):
    """
    Creates app for flask to run
    """
    app = Flask(__name__)
    opt_wrap = DictObj(load_config())
    app.config.from_object(opt_wrap.flask_options)
    app.config['api_options'] = opt_wrap.api_options
    app.config['ui_options'] = opt_wrap.ui_options
    """
    Init plugins
    """
    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login.init_app(app)
    login.login_view = "ui.login"
    metrics.init_app(app)
    register_error_handlers(app)
    from .models import IDSAlert, TargetNetworkID, User, UserAsset, TargetAsset
    with app.app_context():
        from . import apiroutes
        from . import uiroutes
        db.create_all()
        app.register_blueprint(apiroutes.api)
        app.register_blueprint(uiroutes.ui)
        metrics.register_default()
    return app



def load_assets(assets, app):
    """
    Loading the assets from the config into the db allows IDS alerts to be tied
    to the affected assets more directly.
    """
    from .models import TargetAsset, TargetNetworkID
    logging.info("Found %s assets", len(assets))
    with app.app_context():
        new_assets = []
        current_db_assets = [x.name for x in db.session.query(TargetAsset).all()]
        current_db_network_ids = [x.id_string for x in db.session.query(TargetNetworkID).all()]
        for asset in assets:
            try:
                if not asset.asset.name in current_db_assets:
                    new_assets.append(TargetAsset(
                            name=asset.asset.name,
                            value=asset.asset.value,
                        ))
            except:
                db.session.rollback()
        db.session.bulk_save_objects(
            new_assets
        )
        db.session.commit()
        new_network_ids =  []
        for asset in assets:
            for identity in asset.asset.network_names:
                if not identity in current_db_network_ids:
                    new_network_ids.append(TargetNetworkID(
                        id_string=identity,
                        node_id=db.session.query(TargetAsset).filter(
                            TargetAsset.name == asset.asset.name
                        ).with_entities(
                            TargetAsset.id
                        ).first()._data[0])
                    )
        db.session.bulk_save_objects(
            new_network_ids
        )
def load_config():
    """
    Loads a config from the sources set in the args and returns a dict of
    options
    """
    if args.config_file_path:
        try:
            opts = get_config_opts(args.config_file_path, is_api_config=True)
            logging.info("Found config file at %s", args.config_file_path)
            return opts
        except (FileNotFoundError, IsADirectoryError, IOError, KeyError):
            logging.warning(
                "Failed to load config from environment var, trying default path")
            # Try to load from default file
            try:
                opts = get_config_opts(DEFAULT_CONFIG_PATH, is_api_config=True)
                if opts:
                    logging.info("Loaded from default path: %s",
                                 DEFAULT_CONFIG_PATH)
                return opts
            except (FileNotFoundError, IsADirectoryError, IOError, KeyError):
                logging.error("Failed to load both config files, exiting!")
                sys.exit("Config file could not be loaded")
    else:
        try:
            opts = get_config_opts(DEFAULT_CONFIG_PATH, is_api_config=True)
            return opts
        except (FileNotFoundError, IsADirectoryError, IOError):
            logging.error(
                "Failed to load config from default path, and no other file was specified")
            sys.exit("Config file could not be loaded")


def init_app():
    """
    Parse args before loading app into Flask
    """
    # Create app
    app = create_app(args)
    load_assets(app.config['api_options'].registered_assets, app)
    return app
