Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case09OpenRedirect

        Public Function Bad(ctx As HttpContext) As String
            Dim target As String = ctx.Request.Query("next").ToString()
            ctx.Response.Redirect(target)
            Return ""
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim target As String = ctx.Request.Query("next").ToString()
            Dim isLocal As Boolean = target.StartsWith("/", StringComparison.Ordinal) _
                AndAlso Not target.StartsWith("//", StringComparison.Ordinal) _
                AndAlso Not target.StartsWith("/\", StringComparison.Ordinal)
            If Not isLocal Then
                target = "/"
            End If
            ctx.Response.Redirect(target)
            Return ""
        End Function

    End Module

End Namespace
