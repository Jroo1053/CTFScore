from models import IDSAlert
from 

class IDSAlert_DB(IDSAlert,db.Model):
    def __init__(self):
        super().__init__(IDSAlert)
