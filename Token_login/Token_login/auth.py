import jwt
import json
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from datetime import date, datetime , time

def validate_payload(func):
    def wrapper(*args, **kwargs):
        view = args[0]
        request = args[1]
        try:
            payload = json.loads(request.body.decode())
            if request.method in ['POST','PATCH']:
                f = view.form(payload)
                if not f.is_valid():
                    ejson = json.loads(f.errors.as_json())
                    msg = dict([(key, val[0]['message'])
                                for key, val in ejson.items()])
                    return JsonResponse({"error": True, 'msg': msg})
            view.payload = payload
        except json.decoder.JSONDecodeError:
            msg = "Invalid payload format! please check your payload"
            return JsonResponse({'error': True, 'msg': msg})
        return func(*args, **kwargs)
    return wrapper


def authenticate(func):
    def wrapper(*args, **kwargs):
        view = args[0]
        request = args[1]
        headers = request.META
        if "HTTP_AUTHORIZATION" not in headers:
            return HttpResponse(403)
        token = headers["HTTP_AUTHORIZATION"].split()[1]
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.exceptions.InvalidSignatureError:
          return HttpResponse("Invalid Token", status=401)
        return func(*args, **kwargs)
    return wrapper