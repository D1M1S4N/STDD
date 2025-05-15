import unittest
import hashlib
import bcrypt
from icontract import require, ensure
from abc import ABC, abstractmethod
from datetime import datetime,timezone
import logging

import warnings
warnings.filterwarnings("ignore")

class ErrorPoliticaPassword(Exception):
    pass

class ErrorAutenticacion(Exception):
    pass

class ErrorServicioNoEncontrado(Exception):
    pass

class ErrorCredencialExistente(Exception):
    pass

# ---------------------------
# Abstracciones (DIP)
# ---------------------------

class ICifrador(ABC):
    @abstractmethod
    def hash(self, texto: str) -> str: pass

    @abstractmethod
    def verificar(self, texto: str, hash_texto: str) -> bool: pass


class IValidadorPassword(ABC):
    @abstractmethod
    def validar(self, servicio: str, usuario: str, password: str): pass

# ---------------------------
# Secure Strategy Factory
# ---------------------------
            
class SecureStrategyFactory:
    def __init__(self, usuario_roles: dict):
        # Diccionario con usuario -> rol o permisos
        self.usuario_roles = usuario_roles

    def obtener_cifrador(self) -> ICifrador:
        return CifradorBCrypt()  # cifrado fuerte para admin

    def obtener_validador(self) -> IValidadorPassword:
        return ValidadorPasswordSeguro()


# ---------------------------
# Implementaciones concretas
# ---------------------------

class CifradorBCrypt(ICifrador):
    def hash(self, texto: str) -> str:
        return bcrypt.hashpw(texto.encode(), bcrypt.gensalt()).decode()

    def verificar(self, texto: str, hash_texto: str) -> bool:
        return bcrypt.checkpw(texto.encode(), hash_texto.encode())


class ValidadorPasswordSeguro(IValidadorPassword):
    def validar(self, servicio: str, usuario: str, password: str):
        if not servicio or not usuario:
            raise ValueError("El servicio y el usuario no pueden estar vacíos.")
        if len(password) < 8:
            raise ErrorPoliticaPassword("La contraseña debe tener al menos 8 caracteres.")
        if not any(c.isupper() for c in password):
            raise ErrorPoliticaPassword("Debe contener al menos una mayúscula.")
        if not any(c.islower() for c in password):
            raise ErrorPoliticaPassword("Debe contener al menos una minúscula.")
        if not any(c.isdigit() for c in password):
            raise ErrorPoliticaPassword("Debe contener al menos un número.")
        if not any(c in "!@#$%;^&*|'-" for c in password):
            raise ErrorPoliticaPassword("Debe contener un símbolo especial.")
        if any(c in servicio for c in ";|&'-\""):
            raise ErrorPoliticaPassword("Inyección de servicio detectada.")


# ------------------- LOGGER SEGURO -------------------

class LoggerSeguro:
    def __init__(self, ruta_log="registro_seguro.log"):
        self.logger = logging.getLogger("LoggerSeguro")
        self.logger.setLevel(logging.INFO)
        self.file_handler = logging.FileHandler(ruta_log)
        self.logger.addHandler(self.file_handler)
        self.hash_anterior = None
        self.ruta_log = ruta_log

        # Inicializar log
        self._log_inicial()

    def _generar_hash(self, entrada: str) -> str:
        base = (entrada + (self.hash_anterior or "")).encode()
        return hashlib.sha256(base).hexdigest()

    def _log_inicial(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        mensaje = f"Inicialización del log en el tiempo {now} UTC"
        h = self._generar_hash(mensaje)
        linea = f"{now}: INFO     | '{h}': {mensaje} |"
        self.hash_anterior = h
        self.logger.info(linea)

    def registrar(self, tipo: str, usuario: str, mensaje: str):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        linea_sin_hash = f"{now}: {tipo.upper():<8} | {usuario} |"
        hash_actual = self._generar_hash(mensaje)
        linea_completa = f"{linea_sin_hash} '{hash_actual}': {mensaje} |"
        self.hash_anterior = hash_actual
        if tipo.lower() == "info":
            self.logger.info(linea_completa)
        else:
            self.logger.warning(linea_completa)

# ---------------------------
# Clase principal (SRP)
# ---------------------------
    
class GestorCredenciales:
    def __init__(self, clave_maestra: str, cifrador: ICifrador, validador: IValidadorPassword, logger: LoggerSeguro):
        self._cifrador = cifrador
        self._validador = validador
        self._logger = logger
        self._clave_maestra_hashed = self._cifrador.hash(clave_maestra)
        self._credenciales = {}

    def _autenticado(self, clave_maestra: str, usuario: str) -> bool:
        if self._cifrador.verificar(clave_maestra, self._clave_maestra_hashed):
            return True
        self._logger.registrar("WARNING", usuario, "Acceso denegado por clave invalida.")
        raise ErrorAutenticacion("Clave maestra incorrecta.")

    def anyadir_credencial(self, clave_maestra: str, servicio: str, usuario: str, password: str):
        self._autenticado(clave_maestra, usuario)
        self._validador.validar(servicio, usuario, password)
        password_encriptada = self._cifrador.hash(password)
        self._credenciales.setdefault(servicio, {})[usuario] = password_encriptada
        self._logger.registrar("INFO", usuario, f"Llamada a 'añadir_credencial' -> Credencial para '{servicio}' añadida.")

    def obtener_password(self, clave_maestra: str, servicio: str, usuario: str) -> str:
        self._autenticado(clave_maestra, usuario)
        self._logger.registrar("INFO", usuario, f"Llamada a 'obtener_password' -> Recuperada credencial de '{servicio}'.")
        return self._credenciales[servicio][usuario]

    def eliminar_credencial(self, clave_maestra: str, servicio: str, usuario: str):
        self._autenticado(clave_maestra, usuario)
        if servicio in self._credenciales and usuario in self._credenciales[servicio]:
            del self._credenciales[servicio][usuario]
            if not self._credenciales[servicio]:
                del self._credenciales[servicio]
        self._logger.registrar("INFO", usuario, f"Llamada a 'eliminar_credencial' -> Eliminada credencial de '{servicio}'.")

    def listar_servicios(self, clave_maestra: str) -> list:
        if not self._cifrador.verificar(clave_maestra, self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta.")
        return list(self._credenciales.keys())

# ---------------------------
# Secure Proxy para GestorCredenciales
# ---------------------------

class GestorCredencialesProxy:
    def __init__(self, gestor: GestorCredenciales, usuarios_permitidos: dict):
        self._gestor = gestor
        self.usuarios_permitidos = usuarios_permitidos  # usuario -> clave_maestra válida

    def _autenticar(self, usuario: str, clave_maestra: str):
        clave_valida = self.usuarios_permitidos.get(usuario)
        if clave_valida != clave_maestra:
            self._gestor._logger.registrar("WARNING", usuario, "Acceso denegado en proxy por clave incorrecta.")
            raise ErrorAutenticacion("Clave maestra incorrecta en proxy.")
        return True

    def anyadir_credencial(self, usuario: str, clave_maestra: str, servicio: str, usuario_servicio: str, password: str):
        self._autenticar(usuario, clave_maestra)
        return self._gestor.añadir_credencial(clave_maestra, servicio, usuario_servicio, password)

    def obtener_password(self, usuario: str, clave_maestra: str, servicio: str, usuario_servicio: str) -> str:
        self._autenticar(usuario, clave_maestra)
        return self._gestor.obtener_password(clave_maestra, servicio, usuario_servicio)

    def eliminar_credencial(self, usuario: str, clave_maestra: str, servicio: str, usuario_servicio: str):
        self._autenticar(usuario, clave_maestra)
        return self._gestor.eliminar_credencial(clave_maestra, servicio, usuario_servicio)

    def listar_servicios(self, usuario: str, clave_maestra: str) -> list:
        self._autenticar(usuario, clave_maestra)
        return self._gestor.listar_servicios(clave_maestra)