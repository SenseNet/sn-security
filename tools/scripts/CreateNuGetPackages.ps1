$srcPath = [System.IO.Path]::GetFullPath(($PSScriptRoot + '\..\..\src'))

# delete existing packages
Remove-Item $PSScriptRoot\*.nupkg

nuget pack $srcPath\SenseNet.Security.Messaging.Msmq\SenseNet.Security.Messaging.Msmq.nuspec -properties Configuration=Release -OutputDirectory $PSScriptRoot

