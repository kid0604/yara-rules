rule Windows_Trojan_Trickbot_07239dad
{
	meta:
		author = "Elastic Security"
		id = "07239dad-7f9e-4b20-a691-d9538405b931"
		fingerprint = "32d63b8db4307fd67e2c9068e22f843f920f19279c4a40e17cd14943577e7c81"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets vncDll64.dll module containing remote control VNC functionality"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "DBD534F2B5739F89E99782563062169289F23AA335639A9552173BEDC98BB834"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "C:\\Users\\MaxMikhaylov\\Documents\\Visual Studio 2010\\MMVNC.PROXY\\VNCSRV\\x64\\Release\\VNCSRV.pdb" ascii fullword
		$a2 = "vncsrv.dll" ascii fullword
		$a3 = "-new -noframemerging http://www.google.com" ascii fullword
		$a4 = "IE.HTTP\\shell\\open\\command" ascii fullword
		$a5 = "EDGE\\shell\\open\\command" ascii fullword
		$a6 = "/K schtasks.exe |more" ascii fullword
		$a7 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig> " ascii fullword
		$a8 = "\\Microsoft Office\\Office16\\outlook.exe" ascii fullword
		$a9 = "\\Microsoft Office\\Office11\\outlook.exe" ascii fullword
		$a10 = "\\Microsoft Office\\Office15\\outlook.exe" ascii fullword
		$a11 = "\\Microsoft Office\\Office12\\outlook.exe" ascii fullword
		$a12 = "\\Microsoft Office\\Office14\\outlook.exe" ascii fullword
		$a13 = "TEST.TEMP:" ascii fullword
		$a14 = "Chrome_WidgetWin" wide fullword
		$a15 = "o --disable-gpu --disable-d3d11 --disable-accelerated-2d-canvas" ascii fullword
		$a16 = "NetServerStart" ascii fullword

	condition:
		6 of ($a*)
}
