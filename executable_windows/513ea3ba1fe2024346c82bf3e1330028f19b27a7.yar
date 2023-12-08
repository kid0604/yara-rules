rule INDICATOR_TOOL_PWS_Amady
{
	meta:
		author = "ditekSHen"
		description = "Detects password stealer DLL. Dropped by Amadey"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii
		$s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii
		$s3 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii
		$s4 = "\\HostName" fullword ascii
		$s5 = "\\Password" fullword ascii
		$s6 = "SOFTWARE\\RealVNC\\" ascii
		$s7 = "SOFTWARE\\TightVNC\\" ascii
		$s8 = "cred.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 7 of them
}
