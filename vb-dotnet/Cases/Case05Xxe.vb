Imports System.IO
Imports System.Xml
Imports Microsoft.AspNetCore.Http

Namespace VulnVb.Cases

    Public Module Case05Xxe

        Public Function Bad(ctx As HttpContext) As String
            Dim xml As String = ctx.Request.Query("xml").ToString()
            Dim settings As New XmlReaderSettings()
            settings.DtdProcessing = DtdProcessing.Parse
            settings.XmlResolver = New XmlUrlResolver()
            Using sr As New StringReader(xml)
                Using xr As XmlReader = XmlReader.Create(sr, settings)
                    Dim doc As New XmlDocument()
                    doc.Load(xr)
                    Return doc.DocumentElement.InnerText
                End Using
            End Using
        End Function

        Public Function Good(ctx As HttpContext) As String
            Dim xml As String = ctx.Request.Query("xml").ToString()
            Dim settings As New XmlReaderSettings()
            settings.DtdProcessing = DtdProcessing.Prohibit
            settings.XmlResolver = Nothing
            Using sr As New StringReader(xml)
                Using xr As XmlReader = XmlReader.Create(sr, settings)
                    Dim doc As New XmlDocument()
                    doc.XmlResolver = Nothing
                    doc.Load(xr)
                    Return doc.DocumentElement.InnerText
                End Using
            End Using
        End Function

    End Module

End Namespace
