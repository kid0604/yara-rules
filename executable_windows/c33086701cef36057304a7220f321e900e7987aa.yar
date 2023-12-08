import "pe"

rule MALWRE_Win_DarkGate
{
	meta:
		author = "ditekSHen"
		description = "Detects DarkGate infostealer and coinminer"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SYSTEM Elevation: Completed, new DarkGate connection with SYSTEM privileges" ascii
		$x2 = "-u 0xDark" ascii
		$x3 = "DarkGate" ascii
		$x4 = "/c cmdkey /generic:\"127.0.0.2\" /user:\"SafeMode\" /pass:\"darkgatepassword0\"" ascii
		$s1 = "c:\\temp\\crash.txt" ascii
		$s2 = "/cookiesfile \"" ascii
		$s3 = "/c rmdir /s /q \"" ascii
		$s4 = "/c xcopy /E /I /Y \"%s\" \"%s\" && exit" ascii
		$s5 = "U_MemScan" ascii
		$s6 = "U_Google_AD" ascii
		$s7 = "untBotUtils" ascii
		$s8 = "____padoru____" ascii
		$s9 = "u_SysHook" ascii
		$s10 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii
		$s11 = "C:\\Windows\\System32\\ntdll.dll" fullword ascii
		$s12 = /(SYSTEM )?Elevation: (Cannot|I already|AT RAW|FAILURE)/ ascii
		$s13 = /Stub: (WARNING:|Configuration updated:|Global Ping Invoked)/ ascii

	condition:
		( uint16(0)==0x5a4d and ((3 of ($x*)) or (2 of ($x*) and 3 of ($s*)) or (1 of ($x*) and 5 of ($s*)) or (6 of ($s*)))) or (10 of them )
}
