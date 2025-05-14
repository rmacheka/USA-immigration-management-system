from flask_restful import Resource
from app.models import Country, VisaType

class CountryAPI(Resource):
    def get(self):
        """Get list of countries"""
        countries = Country.query.order_by(Country.name).all()
        return [{'code': c.code, 'name': c.name} for c in countries]

class VisaTypeAPI(Resource):
    def get(self):
        """Get list of visa types"""
        visa_types = VisaType.query.order_by(VisaType.name).all()
        return [{'code': v.code, 'name': v.name} for v in visa_types]