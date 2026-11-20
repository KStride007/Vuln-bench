Imports System.Net.Http
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case11Ssrf

        Public Function Bad(ctx As HttpContext) As String
            Dim url As String = ctx.Request.Query("url").ToString()
            Using client As New HttpClient()
                Return client.GetStringAsync(url).GetAwaiter().GetResult()
            End Using
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim url As String = ctx.Request.Query("url").ToString()
            Dim uri As Uri = Nothing
            If Not Uri.TryCreate(url, UriKind.Absolute, uri) OrElse uri.Scheme <> Uri.UriSchemeHttps Then
                Throw New ArgumentException("https URL required")
            End If
            Dim allowed As String() = {"example.com", "api.example.com"}
            If Array.IndexOf(allowed, uri.Host) < 0 Then
                Throw New UnauthorizedAccessException("host not allowed")
            End If
            Using client As New HttpClient()
                Return client.GetStringAsync(uri).GetAwaiter().GetResult()
            End Using
        End Function

    End Module

End Namespace
