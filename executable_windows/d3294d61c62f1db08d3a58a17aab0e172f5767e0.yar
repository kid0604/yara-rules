rule FourElementSword_Keyainst_EXE
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii
		$s1 = "ShellExecuteA" fullword ascii
		$s2 = "GetStartupInfoA" fullword ascii
		$s3 = "SHELL32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <48KB and $x1) or ( all of them )
}
