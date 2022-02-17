from flask import render_template


BASE_DOC_TITLE = "Advanced CTF Scoring System"


def register_error_handlers(app):

    @app.errorhandler(400)
    def handle_bad_request(e):
        title = "Bad Request |" + BASE_DOC_TITLE
        messsage = e.description
        header = e.name
        return render_template("error.html", title=title, messsage=messsage,
                               header=header), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        title = "File Not Found |" + BASE_DOC_TITLE
        message = e.description
        header = e.name
        return render_template("error.html", title=title, message=message,
                               header=header), 404

    @app.errorhandler(405)
    def handle_not_auth(e):
        title = "Not Authorised |" + BASE_DOC_TITLE
        message = e.description
        header = e.name
        return render_template("error.html", title=title, message=message,
                               header=header), 405