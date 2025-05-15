import unittest

import os
import sys

# Ruta absoluta al directorio 'src'
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Ahora ya puedes importar
from gestor_credenciales.utils import saludar

class TestUtils(unittest.TestCase):

    # Tests funcionales
    def test_saludar(self):
        assert saludar("Antonio") == "Hola, Antonio!"

if __name__ == "__main__":
        unittest.main()