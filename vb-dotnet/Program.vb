Imports System.IO
Imports System.Threading.Tasks
Imports Microsoft.AspNetCore.Builder
Imports Microsoft.AspNetCore.Http
Imports VulnVb.Cases

Namespace VulnVb

    Public Module Program

        Public Sub Main(args As String())
            Dim builder = WebApplication.CreateBuilder(args)
            Dim app = builder.Build()

            Directory.CreateDirectory(Case03PathTraversal.BaseDir)
            File.WriteAllText(Path.Combine(Case03PathTraversal.BaseDir, "readme.txt"), "public document")

            Wire(app, "case01", AddressOf Case01SqlInjection.Bad, AddressOf Case01SqlInjection.Good)
            Wire(app, "case02", AddressOf Case02CommandInjection.Bad, AddressOf Case02CommandInjection.Good)
            Wire(app, "case03", AddressOf Case03PathTraversal.Bad, AddressOf Case03PathTraversal.Good)
            Wire(app, "case04", AddressOf Case04Xss.Bad, AddressOf Case04Xss.Good)
            Wire(app, "case05", AddressOf Case05Xxe.Bad, AddressOf Case05Xxe.Good)
            Wire(app, "case06", AddressOf Case06Deserialization.Bad, AddressOf Case06Deserialization.Good)
            Wire(app, "case07", AddressOf Case07WeakHash.Bad, AddressOf Case07WeakHash.Good)
            Wire(app, "case08", AddressOf Case08HardcodedCredentials.Bad, AddressOf Case08HardcodedCredentials.Good)
            Wire(app, "case09", AddressOf Case09OpenRedirect.Bad, AddressOf Case09OpenRedirect.Good)
            Wire(app, "case10", AddressOf Case10InsecureRandom.Bad, AddressOf Case10InsecureRandom.Good)
            Wire(app, "case11", AddressOf Case11Ssrf.Bad, AddressOf Case11Ssrf.Good)
            Wire(app, "case12", AddressOf Case12ReDoS.Bad, AddressOf Case12ReDoS.Good)

#If WITH_DEPS Then
            app.MapGet("/deps", New RequestDelegate(Function(ctx As HttpContext) ctx.Response.WriteAsync(VulnVb.Deps.DepUsage.Describe(New With {.status = "ok"}))))
#End If

            app.MapGet("/", New RequestDelegate(Function(ctx As HttpContext) ctx.Response.WriteAsync("VulnVb: intentionally vulnerable. Routes: /caseNN/bad and /caseNN/good")))

            app.Run()
        End Sub

        Private Sub Wire(app As WebApplication, id As String, bad As Func(Of HttpContext, String), good As Func(Of HttpContext, String))
            app.MapGet("/" & id & "/bad", New RequestDelegate(Function(ctx As HttpContext) Run(ctx, bad)))
            app.MapGet("/" & id & "/good", New RequestDelegate(Function(ctx As HttpContext) Run(ctx, good)))
        End Sub

        Private Function Run(ctx As HttpContext, handler As Func(Of HttpContext, String)) As Task
            ctx.Response.ContentType = "text/html; charset=utf-8"
            Try
                Dim body As String = handler(ctx)
                Return ctx.Response.WriteAsync(If(body, ""))
            Catch ex As Exception
                ctx.Response.StatusCode = 500
                Return ctx.Response.WriteAsync("error: " & ex.GetType().Name & ": " & ex.Message)
            End Try
        End Function

    End Module

End Namespace
