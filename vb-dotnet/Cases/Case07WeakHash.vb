Imports System.Security.Cryptography
Imports System.Text
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case07WeakHash

        Public Function Bad(ctx As HttpContext) As String
            Dim password As String = ctx.Request.Query("password").ToString()
            Dim digest As Byte() = MD5.HashData(Encoding.UTF8.GetBytes(password))
            Return Convert.ToHexString(digest)
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim password As String = ctx.Request.Query("password").ToString()
            Dim salt As Byte() = RandomNumberGenerator.GetBytes(16)
            Dim digest As Byte() = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210000, HashAlgorithmName.SHA256, 32)
            Return Convert.ToHexString(salt) & ":" & Convert.ToHexString(digest)
        End Function

    End Module

End Namespace
