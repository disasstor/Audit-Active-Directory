#Аудит учетнных записей - отключение записи
# $args[0] - token
# $args[1] - chat id
# $args[2] - ip adress or domain name, if you want run script on local machine, use $env:COMPUTERNAME
# Example: \\server.local\audit\4725.ps1 1234567890:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 -1234567890 $env:COMPUTERNAME

$token = $args[0]
$chat_id = $args[1]
$server = $args[2]

$uri = "https://api.telegram.org/bot$token/sendMessage?chat_id=$chat_id&text="
$eventID = "4725"

$event = (Get-WinEvent -ComputerName $server -maxevent 1 -FilterHashtable @{LogName = ”Security”; ID = $eventID } | Select TimeCreated, 
@{n = ”Пользователь”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “TargetUserName” } | % { $_.’#text’ } } },
@{n = ”Администратор”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “SubjectUserName” } | % { $_.’#text’ } } })

$time = $event.TimeCreated
$admin = $event.Администратор
$user = $event.Пользователь

$text = "Пользователь $user выключен администратором $admin"

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
Invoke-WebRequest ` -Uri $uri+$text -Method get
