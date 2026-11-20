Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary
Imports System.Text.Json
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case06Deserialization

        Public Function Bad(ctx As HttpContext) As String
            Dim data As String = ctx.Request.Query("data").ToString()
            Dim bytes As Byte() = Convert.FromBase64String(data)
            Dim formatter As New BinaryFormatter()
            Using ms As New MemoryStream(bytes)
                Dim obj As Object = formatter.Deserialize(ms)
                Return obj.ToString()
            End Using
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim data As String = ctx.Request.Query("data").ToString()
            Dim obj As Dictionary(Of String, String) = JsonSerializer.Deserialize(Of Dictionary(Of String, String))(data)
            Return String.Join(",", obj.Keys)
        End Function

    End Module

End Namespace
