Imports log4net
Imports Newtonsoft.Json

Namespace VulnVb.Deps

    ' Benign use of vulnerable dependency versions. SAST should report nothing here;
    ' SCA should report the packages declared in VulnVb.vbproj. SharpZipLib is declared
    ' but never referenced in code, which tests reachability-aware SCA.
    Public Module DepUsage

        Public Function Describe(value As Object) As String
            LogManager.GetLogger("vulnvb").Info("describe called")
            Return JsonConvert.SerializeObject(value)
        End Function

    End Module

End Namespace
