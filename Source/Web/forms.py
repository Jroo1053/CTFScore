from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FieldList
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired()])
    access_token = PasswordField('Access Token:', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired(),Length(1,32)])
    registered_assets = FieldList(StringField("Network Identifier",
                                              validators=[Length(0,32)]),
                                  min_entries=2, max_entries=32)
    submit = SubmitField("Register")
    """
    append_id = SubmitField("Register Another Asset")
    """

class ConfigureForm(FlaskForm):
    registered_assets = FieldList(StringField("Network Identifier"),
                                              min_entries=3,max_entries=32)
    append_field = SubmitField("Register More Assets")
    submit = SubmitField("Update")
