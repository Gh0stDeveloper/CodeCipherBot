"""Compatibilidad con el nombre antiguo del módulo.

Los proyectos nuevos deben importar desde ``encryption_methods``.
"""

from encryption_methods import *  # noqa: F401,F403
