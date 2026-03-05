# Graph Hunter documentation - Sphinx configuration
# Build: sphinx-build -b html docs docs/_build/html
# Or: cd docs && make html

import os
import re

project = "Graph Hunter"
slug = re.sub(r"\W+", "-", project.lower())
version = "0.1"
release = "0.1.0"
language = "en"
author = "BASE4 Security — Lucas Sotomayor & Diego Staino"
copyright = "BASE4 Security."

extensions = [
    "sphinx_rtd_theme",
    "sphinx.ext.autosectionlabel",
]

# Ensure section labels are unique (e.g. installation, usage)
autosectionlabel_prefix_document = True

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": False,
    "navigation_depth": 4,
    "style_nav_header_background": "#2b2b2b",
}
# Optional: add docs/images/logo.png and set html_logo = "images/logo.png"
# html_logo = "images/logo.png"
html_static_path = ["_static"] if os.path.exists("_static") else []
html_show_sourcelink = True
html_show_copyright = True
html_last_updated_fmt = "%Y-%m-%d"
