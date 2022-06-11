# Аудит локальной группы безопасности - удаление пользователя
# $args[0] - token
# $args[1] - chat id
# $args[2] - ip adress or domain name, if you want run script on local machine, use $env:COMPUTERNAME
# Example: \\server.local\audit\4729.ps1 1234567890:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 -1234567890 $env:COMPUTERNAME

$token = $args[0]
$chat_id = $args[1]
$server = $args[2]

$uri = "https://api.telegram.org/bot$token/sendMessage?chat_id=$chat_id&text="
$eventID = "4733"

$event = (Get-WinEvent -ComputerName $server -maxevent 1 -FilterHashtable @{LogName = ”Security”; ID = $eventID } | Select TimeCreated)
$time = $event.TimeCreated

Start-Sleep -Seconds 2 #ждать 2 секунды

$event2 = (Get-WinEvent -ComputerName $server -maxevent 10 -FilterHashtable @{LogName = ”Security”; ID = $eventID } | Select TimeCreated, 
@{n = ”Группа”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “TargetUserName” } | % { $_.’#text’ } } },
@{n = ”Домен”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “TargetDomainName” } | % { $_.’#text’ } } },
@{n = ”SID-пользователя”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “MemberSid” } | % { $_.’#text’ } } },
@{n = ”Администратор”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “SubjectUserName” } | % { $_.’#text’ } } })

$event2array = New-Object 'System.Collections.Generic.List[System.Object]'
$text = New-Object 'System.Collections.Generic.List[System.Object]'

for ($i = 0; $i -lt $event2.Count; $i++)
{
    if ($event2[$i].TimeCreated -eq $time[0])
    {
    $event2array.Add($event2[$i])
    $eventtextgroup = $event2array[$i].Группа
    $eventtextuser = (Get-ADUser -Identity $event2array[$i].'SID-пользователя').SamAccountName
    $eventtextadmin = $event2array[$i].Администратор
    $text.Add("Локальная группа безопасности: $eventtextgroup%0AУдален пользователь: $eventtextuser%0AАдминистратором: $eventtextadmin%0AСервер: $server%0A---------------%0A")
    }
}

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
Invoke-WebRequest ` -Uri $uri+$text -Method get