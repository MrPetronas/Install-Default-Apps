#UserFiles Does not work on windows 10 20h2

#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 0
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu\' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 0


#This PC Does not work on windows 10 20h2
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu\' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0

#Disable Windows Fast boot
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power\' -Name 'HiberbootEnabled' -Value 0

#set to never sleep
Powercfg /x -standby-timeout-ac 0


$url1 = "https://ninite.com/7zip-chrome-firefox-notepadplusplus-vlc/ninite.exe"
$output1 = "~\Downloads\ninite.exe"


$url2 = "https://admdownload.adobe.com/bin/live/readerdc_en_a_install.exe"
$output2 = "~\Downloads\readerdc_en_a_install.exe"


Invoke-WebRequest -Uri $url1 -OutFile $output1
sleep -s 5
Start-Process -FilePath "$output1" -Verb RunAs

$temp = Get-CimInstance -ClassName Win32_ComputerSystem | select Model; $site = "https://www.google.com/search?q="+ $temp.Model + " Drivers"; start $site

Invoke-WebRequest -Uri $url2 -OutFile $output2
sleep -s 240
Start-Process -FilePath "$output2" -Verb RunAs

$javadowload = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=244581_d7fc238d0cbf4b0dac67be84580cfb4b"
$javadowloadlocal = "~\Downloads\java.exe"

Invoke-WebRequest -Uri $javadowload -OutFile $javadowloadlocal
sleep -s 120
Start-Process -FilePath "$javadowloadlocal" -Verb RunAs

if((read-host "ar reikia office 365? jei ne spauskite N ir Enter") -like "n")
{
    Write-Host "neirasom"
}else{
    Write-Host "irasom"

    $o365xml = "https://github.com/MrPetronas/Install-Default-Apps/raw/master/0365MonthlyConfiguration.xml"
    $o365xmllocal = "~\desktop\0365MonthlyConfiguration.xml"


    Invoke-WebRequest -Uri $o365xml -OutFile $o365xmllocal
    sleep -s 1    

    $office365Setupexe = "https://github.com/MrPetronas/Install-Default-Apps/raw/master/setup.exe"
    $office365Setupexelocal = "~\desktop\setup.exe"


    Invoke-WebRequest -Uri $office365Setupexe -OutFile $office365Setupexelocal
    sleep -s 2
    Start-Process -FilePath "$office365Setupexelocal" -Verb RunAs -ArgumentList "/configure C:\Users\Administrator\desktop\0365MonthlyConfiguration.xml"
    
    #appAssociasions
    $appassociationsxml = "https://raw.githubusercontent.com/MrPetronas/Install-Default-Apps/master/AppAssociations.xml"
    $appassociationsxmllocal = "c:\AppAssociations.xml"


    Invoke-WebRequest -Uri $appassociationsxml -OutFile $appassociationsxmllocal
    sleep -s 1    

    Dism /Online /import-DefaultAppAssociations:"C:\AppAssociations.xml"
    
}






$userName = "administrator"
Enable-LocalUser -Name $userName
Write-Host "Suvesk lokalaus Admin PSW"
$Password = Read-Host
$Password = (convertto-securestring $Password -AsPlainText -Force)


Set-LocalUser -Name $userName -Password $Password
Set-LocalUser -Name $userName -PasswordNeverExpires 1
Set-LocalUser -Name $userName -AccountNeverExpires

Get-ChildItem -Path C:\Users\Public\Desktop\ | Remove-Item

Get-ChildItem -Path C:\Users\administrator\Desktop\  | Remove-Item

Write-Host "Suvesk kompiuterio Varda"
$PCname = Read-Host
Rename-Computer -NewName "$PCname"

#enables computer restore point
Enable-ComputerRestore -Drive "C:\"
