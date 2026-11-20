Imports System.Text.RegularExpressions
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case12ReDoS

        Public Function Bad(ctx As HttpContext) As String
            Dim input As String = ctx.Request.Query("value").ToString()
            Return Regex.IsMatch(input, "^(a+)+$").ToString()
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim input As String = ctx.Request.Query("value").ToString()
            Return Regex.IsMatch(input, "^a+$", RegexOptions.None, TimeSpan.FromMilliseconds(100)).ToString()
        End Function

    End Module

End Namespace
