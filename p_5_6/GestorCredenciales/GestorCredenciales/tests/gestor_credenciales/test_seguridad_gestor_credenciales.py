import unittest
import os
import sys
from hypothesis.strategies import text, characters
from hypothesis import settings

# Ruta absoluta al directorio 'src'
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Ahora ya puedes importar
from gestor_credenciales.gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion,CifradorBCrypt,ValidadorPasswordSeguro,LoggerSeguro,GestorCredencialesProxy,SecureStrategyFactory
from hypothesis import given
from hypothesis.strategies import text

class TestSeguridadGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.clave_maestra = "claveMaestraSegura123!"
        self.usuario_admin = "admin"
        self.gestor = GestorCredenciales(self.clave_maestra, cifrador=CifradorBCrypt(), validador=ValidadorPasswordSeguro(), logger=LoggerSeguro())
        self.proxy = GestorCredencialesProxy(self.gestor,usuarios_permitidos={self.usuario_admin: self.clave_maestra})

    # Tests de seguridad

    def test_password_no_almacenado_en_plano(self):
        servicio = "GitHub"
        usuario = "user1"
        password = "PasswordSegura123!"

        self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, servicio, usuario, password)

        stored_password = self.gestor._credenciales[servicio][usuario]
        self.assertNotEqual(stored_password, password)
        self.assertIsInstance(stored_password, str)
        self.assertGreater(len(stored_password), 20)
        self.assertNotIn(password, stored_password)

    def test_deteccion_inyeccion_servicio(self):
        casos_inyeccion = ["serv;icio", "servicio|mal", "servicio&", "servicio'--"]
        for servicio in casos_inyeccion:
            with self.subTest(servicio=servicio):
                with self.assertRaises(ErrorPoliticaPassword):
                    self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, servicio, "usuario_test", "PasswordSegura123!")

    @settings(deadline=None)
    @given(text(alphabet=characters(whitelist_categories=('Ll', 'Lu', 'Nd', 'Po')), min_size=8, max_size=10))
    def test_fuzz_politica_passwords_con_passwords_debiles(self, contrasena_generada):
        try:
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "servicio", "usuario", contrasena_generada)
        except ErrorPoliticaPassword:
            pass
        except Exception as e:
            self.fail(f"Se lanzó una excepción inesperada: {e}")

    def test_politica_passwords_con_password_robusta(self):
        servicio = "TestService"
        usuario = "usuarioTest"
        password_robusta = "ContrasenaSegura123!"

        try:
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, servicio, usuario, password_robusta)
        except ErrorPoliticaPassword:
            self.fail("Se rechazó una contraseña que debería ser válida.")

    def test_acceso_con_clave_maestra_erronea(self):
        self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user1", "PasswordSegura123!")

        with self.assertRaises(ErrorAutenticacion):
            self.proxy.obtener_password(self.usuario_admin, "claveIncorrecta", "GitHub", "user1")

    def test_password_too_short(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user", "P1!aB")

    def test_password_without_uppercase(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user", "password123!")

    def test_password_without_lowercase(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user", "PASSWORD123!")

    def test_password_without_digit(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user", "PasswordSegura!")

    def test_password_without_special_char(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.proxy.añadir_credencial(self.usuario_admin, self.clave_maestra, "GitHub", "user", "Password1234")

if __name__ == "__main__":
    unittest.main()
