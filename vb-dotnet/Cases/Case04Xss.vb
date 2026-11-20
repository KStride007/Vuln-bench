Imports System.Net
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case04Xss

        Public Function Bad(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("name").ToString()
            Return "<html><body><h1>Hello " & name & "</h1></body></html>"
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("name").ToString()
            Return "<html><body><h1>Hello " & WebUtility.HtmlEncode(name) & "</h1></body></html>"
        End Function

    End Module

End Namespace
