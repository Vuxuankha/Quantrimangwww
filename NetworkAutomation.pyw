"""Silent source launcher for Windows.

Double-clicking this file with Python installed uses pythonw.exe and therefore
shows only the Tkinter GUI. Production users should use NetworkAutomation.exe.
"""
import runpy
runpy.run_module("main", run_name="__main__")
