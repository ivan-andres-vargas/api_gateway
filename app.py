import datetime
import re

from flask import Flask
from flask import request
from flask import jsonify
from waitress import serve

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS

import json
import requests

app = Flask(__name__)
CORS(app)

# JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "12345"
jwt = JWTManager(app)


@app.route('/candidatos', methods=["GET"])
def consulta_candidatos():
    headers = {"Content-Type": "application/json; charset=utf8"}
    config = cargar_config()
    url = config['url-ms-votaciones'] + "/candidatos"
    respuesta = requests.get(url, headers=headers)
    json = respuesta.json()
    return jsonify(json)


@app.route('/candidatos', methods=["POST"])
def crear_candidatos():
    datosEntrada = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf8"}
    config = cargar_config()
    url = config['url-ms-votaciones'] + "/candidatos"
    respuesta = requests.post(url, json=datosEntrada, headers=headers)
    json = respuesta.json()
    return jsonify(json)


@app.route('/candidatos', methods=["PUT"])
def actualizar_candidatos():
    datosEntrada = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf8"}
    config = cargar_config()
    url = config['url-ms-votaciones'] + "/candidatos"
    respuesta = requests.put(url, json=datosEntrada, headers=headers)
    json = respuesta.json()
    return jsonify(json)


@app.route('/candidatos', methods=["DELETE"])
def eliminar_candidatos():
    datosEntrada = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf8"}
    config = cargar_config()
    url = config['url-ms-votaciones'] + "/candidatos"
    respuesta = requests.delete(url, json=datosEntrada, headers=headers)
    json = respuesta.json()
    return jsonify(json)


@app.route('/')
def home():  # put application's code here
    print("PATH HOME")
    return 'API GATEWAY IT IS RUNING MOTHERFUCKER...'


@app.route("/login", methods=["POST"])
def inicio_sesion():
    datos_entrada = request.get_json()
    config = cargar_config()
    headers = {"Content-Type": "application/json; charset=utf8"}
    respuesta = requests.post(config["url-ms-seguridad"] + "/usuarios/login", json=datos_entrada, headers=headers)
    print(respuesta.status_code)

    if respuesta.status_code == 200:
        tiempo_caducidad_token = datetime.timedelta()
        usuario = respuesta.json()
        token_acceso = create_access_token(identity=usuario, expires_delta=tiempo_caducidad_token)
        return {"token_acceso": token_acceso}
    else:
        return jsonify({"mensaje": "Verificar usuario y/o contraseña"})


# CONFIGURACIÓN DEL SERVIDOR CON ARCHIVO CONFIG
def cargar_config():
    with open("Configuración/config.json") as archivo:
        _datos_configuracion = json.load(archivo)
    return _datos_configuracion


if __name__ == '__main__':
    datos_configuracion = cargar_config()
    print('Servidor ejecutandose...' + " " + "http://" + datos_configuracion["url-api-gateway"] + ":" +
          str(datos_configuracion["puerto-api-gateway"]))
    serve(app, host=datos_configuracion["url-api-gateway"], port=datos_configuracion["puerto-api-gateway"])


# -------------------------- #

# MIDDLEWARE

def validarPermiso(endPoint, metodo, idRol):
    config = cargar_config()
    url = config["url-ms-seguridad"] + "/rolpermiso/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=uft-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.post(url, json=body, headers=headers)
    try:
        data = response.json()
        if "id" in data:
            tienePermiso = True
    except:
        pass
    return tienePermiso


def limpiarURl(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


@app.before_request
def verificar_peticion():
    print("Ejecución de callback")

    endPoint = limpiarURl(request.path)
    excludesRoutes = ["/login", "/candidatos"]
    if excludesRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePermiso:
                return jsonify({"mensaje": "Permiso Denegado"}), 401
            else:
                return jsonify({"mensaje": "Permiso Denegado"}), 401
