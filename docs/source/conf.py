import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))

project = "AEGIS-ZERO Reference Model"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx_autodoc_typehints",
]

napoleon_use_ivar = True

templates_path = ["_templates"]

autosummary_generate = True
autodoc_member_order = "bysource"

html_theme = "furo"
