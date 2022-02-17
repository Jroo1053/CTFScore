from Web import init_app, metrics
import flask_monitoringdashboard as dash
from flask_cors import CORS

app = init_app()
CORS(app)

dash.bind(app)

if __name__ == "__main__":
    
    app.run(host="0.0.0.0",threaded=True)