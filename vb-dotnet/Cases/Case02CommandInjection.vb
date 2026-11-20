Imports System.Diagnostics
Imports System.Text.RegularExpressions
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case02CommandInjection

        Public Function Bad(ctx As HttpContext) As String
            Dim host As String = ctx.Request.Query("host").ToString()
            Dim psi As New ProcessStartInfo("/bin/sh")
            psi.RedirectStandardOutput = True
            psi.ArgumentList.Add("-c")
            psi.ArgumentList.Add("echo lookup " & host)
            Using p As Process = Process.Start(psi)
                Dim output As String = p.StandardOutput.ReadToEnd()
                p.WaitForExit()
                Return output
            End Using
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim host As String = ctx.Request.Query("host").ToString()
            If Not Regex.IsMatch(host, "^[A-Za-z0-9.-]{1,253}$") Then
                Throw New ArgumentException("invalid host")
            End If
            Dim psi As New ProcessStartInfo("/bin/echo")
            psi.RedirectStandardOutput = True
            psi.ArgumentList.Add("lookup")
            psi.ArgumentList.Add(host)
            Using p As Process = Process.Start(psi)
                Dim output As String = p.StandardOutput.ReadToEnd()
                p.WaitForExit()
                Return output
            End Using
        End Function

    End Module

End Namespace
