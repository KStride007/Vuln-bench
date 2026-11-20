Imports System.IO
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case03PathTraversal

        Public ReadOnly BaseDir As String = Path.Combine(AppContext.BaseDirectory, "docs")

        Public Function Bad(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("file").ToString()
            Dim path As String = System.IO.Path.Combine(BaseDir, name)
            Return File.ReadAllText(path)
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("file").ToString()
            Dim root As String = System.IO.Path.GetFullPath(BaseDir) & System.IO.Path.DirectorySeparatorChar
            Dim full As String = System.IO.Path.GetFullPath(System.IO.Path.Combine(BaseDir, name))
            If Not full.StartsWith(root, StringComparison.Ordinal) Then
                Throw New UnauthorizedAccessException("path outside document root")
            End If
            Return File.ReadAllText(full)
        End Function

    End Module

End Namespace
