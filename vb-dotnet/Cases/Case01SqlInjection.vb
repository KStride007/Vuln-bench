Imports System.Data.Common
Imports System.Text
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case01SqlInjection

        ' No database provider ships in the base framework. Wire one (for example
        ' Microsoft.Data.Sqlite) here to make these endpoints execute end to end.
        Private Function OpenConnection() As DbConnection
            Throw New NotSupportedException("no ADO.NET provider configured")
        End Function

        Public Function Bad(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("name").ToString()
            Using conn As DbConnection = OpenConnection()
                Using cmd As DbCommand = conn.CreateCommand()
                    cmd.CommandText = "SELECT id, email FROM users WHERE name = '" & name & "'"
                    Using r As DbDataReader = cmd.ExecuteReader()
                        Dim sb As New StringBuilder()
                        While r.Read()
                            sb.Append(r.GetValue(0)).Append(","c).Append(r.GetValue(1)).Append(vbLf)
                        End While
                        Return sb.ToString()
                    End Using
                End Using
            End Using
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim name As String = ctx.Request.Query("name").ToString()
            Using conn As DbConnection = OpenConnection()
                Using cmd As DbCommand = conn.CreateCommand()
                    cmd.CommandText = "SELECT id, email FROM users WHERE name = @name"
                    Dim p As DbParameter = cmd.CreateParameter()
                    p.ParameterName = "@name"
                    p.Value = name
                    cmd.Parameters.Add(p)
                    Using r As DbDataReader = cmd.ExecuteReader()
                        Dim sb As New StringBuilder()
                        While r.Read()
                            sb.Append(r.GetValue(0)).Append(","c).Append(r.GetValue(1)).Append(vbLf)
                        End While
                        Return sb.ToString()
                    End Using
                End Using
            End Using
        End Function

    End Module

End Namespace
