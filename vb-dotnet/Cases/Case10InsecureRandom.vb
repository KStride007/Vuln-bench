Imports System.Security.Cryptography
Imports System.Text
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case10InsecureRandom

        Public Function Bad(ctx As HttpContext) As String
            Dim rnd As New Random()
            Dim sb As New StringBuilder()
            For i As Integer = 0 To 15
                sb.Append(rnd.Next(0, 16).ToString("x"))
            Next
            Return "reset-token=" & sb.ToString()
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim bytes As Byte() = RandomNumberGenerator.GetBytes(16)
            Return "reset-token=" & Convert.ToHexString(bytes)
        End Function

    End Module

End Namespace
