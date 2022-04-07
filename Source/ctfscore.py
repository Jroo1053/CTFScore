from Web import init_app, metrics
import flask_monitoringdashboard as dash
from flask_cors import CORS
import logging

logger = logging.getLogger(__name__)

app = init_app()
CORS(app)

try:
    if app.config['ui_options'].monitoring_stack.flask_dashboard.enabled:
        dash.bind(app)
except KeyError as config_error:
    logging.ERROR("Tried To load monitoring stack options but failed")

if __name__ == "__main__":
    
    app.run(host="0.0.0.0",threaded=True)