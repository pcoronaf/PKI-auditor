"""Puente entre el nucleo de Python y una interfaz grafica.

La interfaz lanza ``python -m firmascope.gui_bridge.bridge``. Por eso este
paquete no importa ``bridge`` al cargarse: si lo hiciera, el modulo se cargaria
dos veces, una como parte del paquete y otra como ``__main__``.
"""
