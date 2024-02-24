import "pe"

rule SUSP_ScreenConnect_Exploitation_Artefacts_Feb24 : SCRIPT
{
	meta:
		description = "Detects post exploitation indicators observed by HuntressLabs in relation to the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		os = "windows"
		filetype = "script"

	strings:
		$x01 = "-c foreach ($disk in Get-WmiObject Win32_Logicaldisk){Add-MpPreference -ExclusionPath $disk.deviceid}"
		$x02 = ".msi c:\\mpyutd.msi"
		$x03 = "/MyUserName_$env:UserName"
		$x04 = " -OutFile C:\\Windows\\Help\\"
		$x05 = "/Create /TN \\\\Microsoft\\\\Windows\\\\Wininet\\\\UserCache_"
		$x06 = "$e = $r + \"ssh.exe\""
		$x07 = "Start-Process -f $e -a $args -PassThru -WindowStyle Hidden).Id"
		$x08 = "-R 9595:localhost:3389 -p 443 -N -oStrictHostKeyChecking=no "
		$x09 = "chromeremotedesktophost.msi', $env:ProgramData+"
		$x10 = "9595; iwr -UseBasicParsing "
		$x11 = "curl  https://cmctt.]com/pub/media/wysiwyg/"
		$x12 = ":8080/servicetest2.dll"
		$x13 = "/msappdata.msi c:\\mpyutd.msi"
		$x14 = "/svchost.exe -OutFile "
		$x15 = "curl http://minish.wiki.gd"
		$x16 = " -Headers @{'ngrok-skip-browser-warning'='true'} -OutFile "
		$x17 = "rundll32.exe' -Headers @"
		$x18 = "/nssm.exe' -Headers @"
		$x19 = "c:\\programdata\\update.dat UpdateSystem"
		$x20 = "::size -eq 4){\\\"TVqQAA" ascii wide
		$x21 = "::size -eq 4){\"TVqQAA" ascii wide
		$x22 = "-nop -c [System.Reflection.Assembly]::Load(([WmiClass]'root\\cimv2:System_"
		$xp0 = "/add default test@2021! /domain"
		$xp1 = "/add default1 test@2021! /domain"
		$xp2 = "oldadmin Pass8080!!"
		$xp3 = "temp 123123qwE /add "
		$xp4 = "oldadmin \"Pass8080!!\""
		$xp5 = "nssm set xmrig AppDirectory "

	condition:
		1 of ($x*)
}
