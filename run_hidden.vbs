Option Explicit

Dim shell, fso, projectDir, pythonExe, command, result
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

projectDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonExe = projectDir & "\.venv\Scripts\python.exe"
command = "schtasks.exe /Run /TN " & Chr(34) & "DangoLocal-WebUI" & Chr(34)

If Not fso.FileExists(pythonExe) Then
    MsgBox "Python virtual environment not found: " & pythonExe, vbCritical, "Dango WebUI"
    WScript.Quit 1
End If

shell.CurrentDirectory = projectDir
result = shell.Run(command, 0, True)
If result <> 0 Then
    MsgBox "Cannot start the DangoLocal-WebUI task. See DEPLOYMENT.md in " & projectDir, vbCritical, "Dango WebUI"
End If
WScript.Quit result
