Option Explicit

Dim shell, fso, projectDir, pythonExe, command, appUrl, readyUrl, i, result
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

projectDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonExe = projectDir & "\.venv\Scripts\python.exe"
appUrl = "http://127.0.0.1:8765/"
readyUrl = appUrl & "api/ready"

If Not fso.FileExists(pythonExe) Then
    MsgBox "Python virtual environment not found: " & pythonExe, vbCritical, "Dango WebUI"
    WScript.Quit 1
End If

If Not IsServiceReady(readyUrl) Then
    command = "schtasks.exe /Run /TN " & Chr(34) & "DangoLocal-WebUI" & Chr(34)
    shell.CurrentDirectory = projectDir
    result = shell.Run(command, 0, True)
    If result <> 0 Then
        MsgBox "Cannot start the DangoLocal-WebUI task. See DEPLOYMENT.md in " & projectDir, vbCritical, "Dango WebUI"
        WScript.Quit 1
    End If

    For i = 1 To 120
        WScript.Sleep 250
        If IsServiceReady(readyUrl) Then Exit For
    Next
End If

If IsServiceReady(readyUrl) Then
    shell.Run appUrl, 1, False
Else
    MsgBox "Dango WebUI did not become ready. Check service-status.log in " & projectDir, vbExclamation, "Dango WebUI"
    WScript.Quit 1
End If

Function IsServiceReady(url)
    Dim request
    On Error Resume Next
    Set request = CreateObject("WinHttp.WinHttpRequest.5.1")
    request.SetTimeouts 500, 500, 500, 500
    request.Open "GET", url, False
    request.Send
    IsServiceReady = (Err.Number = 0 And request.Status = 200)
    Set request = Nothing
    Err.Clear
    On Error GoTo 0
End Function
