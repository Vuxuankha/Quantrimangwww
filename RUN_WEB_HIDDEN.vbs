Option Explicit
Dim fso, root, shell, command
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = root
command = """" & root & "\.venv\Scripts\pythonw.exe"" """ & root & "\run_web_background.py"""
shell.Run command, 0, False
