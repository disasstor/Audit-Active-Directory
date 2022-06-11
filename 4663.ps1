# Аудит удаления файлов

# $args[0] - token
# $args[1] - chat id
# $args[2] - ip adress or domain name, if you want run script on local machine, use $env:COMPUTERNAME
# Example: \\server.local\audit\4663.ps1 1234567890:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 -1234567890 $env:COMPUTERNAME

$token = $args[0]
$chat_id = $args[1]
$server = $args[2]

$uri = "https://api.telegram.org/bot$token/sendMessage?chat_id=$chat_id&text="
$eventID = "4663"

$event = (Get-WinEvent -ComputerName $server -maxevent 1 -FilterHashtable @{LogName = ”Security”; ID = $eventID } | Select TimeCreated)
$time = $event.TimeCreated

Start-Sleep -Seconds 2 #ждать 2 секунды

$event = (Get-WinEvent -ComputerName $server -maxevent 50 -FilterHashtable @{LogName = ”Security”; ID = $eventID } | Select TimeCreated, 
@{n = ”Имя объекта”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “ObjectName” } | % { $_.’#text’ } } },
@{n = ”Пользователь”; e = { ([xml]$_.ToXml()).Event.EventData.Data | ? { $_.Name -eq “SubjectUserName” } | % { $_.’#text’ } } })

$event = $event | sort Пользователь #сортировка по графе "пользователь"

$array = New-Object 'System.Collections.Generic.List[System.Object]'
for ($i = 0; $i -lt $event.Count; $i++)
{
    if (($event[$i].'Имя объекта' -notlike "*.tmp*") -and ($event[$i].'Имя объекта' -notlike "*~$*"))
    {
    $array.Add($event[$i])
    }
}

$array = $array | group Пользователь #группирова по графе "Пользователь"

$text = New-Object 'System.Collections.Generic.List[System.Object]'
for ($i = 0; $i -lt $array.Count; $i++)
{
    if($array[$i].Count -gt 20) #мин колличество событий удаления
    {
    $eventcount = $array[$i].Count
    $user = $array[$i].Name
    $path = $array[$i].Group.'Имя объекта'
    $path1 = $path[0]
    $path1 = $path1.Split("\")
    $path11 = $path1[1]
    $path12 = $path1[2]
    $path13 = $path1[3]
    $text.Add("Пользователь: $user%0AСобытий удаления: $eventcount%0AДиректории: $path11\$path12\$path13%0AСервер: $server%0A---------------%0A")
    }
}
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
Invoke-WebRequest ` -Uri $uri+$text -Method get