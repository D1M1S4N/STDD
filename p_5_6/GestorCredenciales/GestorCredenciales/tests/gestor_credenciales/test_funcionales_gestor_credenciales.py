import unittest
import os

import os
import sys

# Ruta absoluta al directorio 'src'
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Ahora ya puedes importar
from gestor_credenciales.gestor_credenciales import (GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion,CifradorBCrypt, ValidadorPasswordSeguro, LoggerSeguro,GestorCredencialesProxy, SecureStrategyFactory)

from hypothesis import given
from hypothesis.strategies import text


"""class TestFuncionalesGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.gestor = GestorCredenciales("claveMaestraSegura123!",cifrador=CifradorBCrypt(),validador=ValidadorPasswordSeguro(),logger=LoggerSeguro())

    # Tests funcionales
    def test_añadir_credencial(self):
        # Credenciales válidas
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "Password123!")

        # Verificar que las credenciales fueron añadidas correctamente
        password_encriptada = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user1")
        self.assertIsNotNone(password_encriptada)  # La contraseña cifrada no debe ser None

        # Intentar añadir con una clave maestra incorrecta
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.añadir_credencial("claveIncorrecta", "GitHub", "user2", "Password123!")


    def test_recuperar_credencial(self):
        # Añadir una credencial primero
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "Password123!")

        # Recuperar la contraseña encriptada para ese servicio y usuario
        password_encriptada = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user1")
        self.assertIsNotNone(password_encriptada)  # Verificar que se obtuvo la contraseña

        # Intentar recuperar una contraseña con una clave maestra incorrecta
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.obtener_password("claveIncorrecta", "GitHub", "user1")
        
        # Intentar recuperar una contraseña para un servicio que no existe
        with self.assertRaises(KeyError):
            self.gestor.obtener_password("claveMaestraSegura123!", "NonExistentService", "user1")


    def test_listar_servicios(self):
        # Añadir algunas credenciales
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "Password123!")
        self.gestor.añadir_credencial("claveMaestraSegura123!", "Twitter", "user2", "Password123!")

        # Listar los servicios y verificar que "GitHub" y "Twitter" estén presentes
        servicios = self.gestor.listar_servicios("claveMaestraSegura123!")
        self.assertIn("GitHub", servicios)
        self.assertIn("Twitter", servicios)

        # Intentar listar los servicios con una clave maestra incorrecta
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.listar_servicios("claveIncorrecta")"""

class TestFuncionalesGestorCredenciales(unittest.TestCase):
    def setUp(self):
        usuarios_roles = {
            "admin": "admin",
            "user1": "usuario"
        }
        usuarios_claves = {
            "admin": "claveMaestraSegura123!",
            "user1": "claveMaestraSegura123!"
        }
        fabrica = SecureStrategyFactory(usuarios_roles)
        cifrador = fabrica.obtener_cifrador("admin")
        validador = fabrica.obtener_validador("admin")
        logger = LoggerSeguro()
        gestor = GestorCredenciales("claveMaestraSegura123!", cifrador, validador, logger)
        self.proxy = GestorCredencialesProxy(gestor, usuarios_claves)

    def test_añadir_credencial(self):
        self.proxy.añadir_credencial("admin", "claveMaestraSegura123!", "GitHub", "user1", "Password123!")

        password_encriptada = self.proxy.obtener_password("admin", "claveMaestraSegura123!", "GitHub", "user1")
        self.assertIsNotNone(password_encriptada)

        with self.assertRaises(ErrorAutenticacion):
            self.proxy.añadir_credencial("admin", "claveIncorrecta", "GitHub", "user2", "Password123!")

    def test_recuperar_credencial(self):
        self.proxy.añadir_credencial("admin", "claveMaestraSegura123!", "GitHub", "user1", "Password123!")

        password_encriptada = self.proxy.obtener_password("admin", "claveMaestraSegura123!", "GitHub", "user1")
        self.assertIsNotNone(password_encriptada)

        with self.assertRaises(ErrorAutenticacion):
            self.proxy.obtener_password("admin", "claveIncorrecta", "GitHub", "user1")

        with self.assertRaises(KeyError):
            self.proxy.obtener_password("admin", "claveMaestraSegura123!", "NonExistentService", "user1")

    def test_listar_servicios(self):
        # Añadir algunas credenciales usando proxy
        self.proxy.añadir_credencial("admin", "claveMaestraSegura123!", "GitHub", "user1", "Password123!")
        self.proxy.añadir_credencial("admin", "claveMaestraSegura123!", "Twitter", "user2", "Password123!")

        # Listar los servicios y verificar que "GitHub" y "Twitter" estén presentes
        servicios = self.proxy.listar_servicios("admin", "claveMaestraSegura123!")
        self.assertIn("GitHub", servicios)
        self.assertIn("Twitter", servicios)

        # Intentar listar los servicios con una clave maestra incorrecta
        with self.assertRaises(ErrorAutenticacion):
            self.proxy.listar_servicios("admin", "claveIncorrecta")

if __name__ == "__main__":
    unittest.main()
