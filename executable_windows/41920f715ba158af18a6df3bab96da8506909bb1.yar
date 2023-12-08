rule CN_Honker_Interception3389_setup
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file setup.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f5b2f86f8e7cdc00aa1cb1b04bc3d278eb17bf5c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii
		$s1 = "%s\\temp\\temp%d.bat" fullword ascii
		$s5 = "EventStartShell" fullword ascii
		$s6 = "del /f /q \"%s\"" fullword ascii
		$s7 = "\\wminotify.dll" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
