from flask import Flask, request
from flask_restful import Resource, Api, abort
from RESTAPI.urlclass import Url
from RESTAPI.model import *

app = Flask(__name__)
api = Api(app)


class BasicURL(Resource):
    def get(self):
        if 'url' not in request.args.keys():
            abort(400)
        url = Url(request.args['url'])
        res = get_prediction(url)[0]
        detail = generate_result(url)
        detail['result'] = res
        return detail


class LiveURL(Resource):
    def get(self):
        if 'url' not in request.args.keys():
            abort(400)
        url = Url(request.args['url'])
        return {'live': 'world'}

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET')
    return response


api.add_resource(BasicURL, '/basic')
api.add_resource(LiveURL, '/live')

if __name__ == '__main__':
    app.run(debug=True, port=5001)