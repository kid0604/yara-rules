rule SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL
{
	meta:
		description = "Detects PDB strings used in backdoors or keyloggers"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-03-23"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\\Release\\PrivilegeEscalation"
		$ = "\\Release\\KeyLogger"
		$ = "\\Debug\\PrivilegeEscalation"
		$ = "\\Debug\\KeyLogger"
		$ = "Backdoor\\KeyLogger_"
		$ = "\\ShellCode\\Debug\\"
		$ = "\\ShellCode\\Release\\"
		$ = "\\New Backdoor"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}
