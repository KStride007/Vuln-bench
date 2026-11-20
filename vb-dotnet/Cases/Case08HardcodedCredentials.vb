Imports System.Security.Cryptography
Imports System.Text
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case08HardcodedCredentials

        Public Function Bad(ctx As HttpContext) As String
            Dim supplied As String = ctx.Request.Query("password").ToString()
            Dim adminPassword As String = "Winter2024!Prod"
            If supplied = adminPassword Then
                Return "welcome admin"
            End If
            Return "denied"
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim supplied As String = ctx.Request.Query("password").ToString()
            Dim adminPassword As String = Environment.GetEnvironmentVariable("ADMIN_PASSWORD")
            If String.IsNullOrEmpty(adminPassword) Then
                Return "denied"
            End If
            If CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(supplied), Encoding.UTF8.GetBytes(adminPassword)) Then
                Return "welcome admin"
            End If
            Return "denied"
        End Function

    End Module

End Namespace
