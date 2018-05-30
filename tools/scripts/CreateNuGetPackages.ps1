$srcPath = [System.IO.Path]::GetFullPath(($PSScriptRoot + '\..\..\src'))

# delete existing packages
Remove-Item $PSScriptRoot\*.nupkg

nuget pack $srcPath\SenseNet.Security\SenseNet.Security.nuspec -properties Configuration=Release -OutputDirectory $PSScriptRoot
nuget pack $srcPath\SenseNet.Security.EF6SecurityStore\SenseNet.Security.EF6SecurityStore.nuspec -properties Configuration=Release -OutputDirectory $PSScriptRoot
nuget pack $srcPath\SenseNet.Security.Messaging.Msmq\SenseNet.Security.Messaging.Msmq.nuspec -properties Configuration=Release -OutputDirectory $PSScriptRoot
nuget pack $srcPath\SenseNet.Security.Messaging.RabbitMQ\SenseNet.Security.Messaging.RabbitMQ.nuspec -properties Configuration=Release -OutputDirectory $PSScriptRoot

