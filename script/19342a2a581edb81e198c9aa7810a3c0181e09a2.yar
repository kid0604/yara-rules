rule CN_Honker_Webshell_cfmShell
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "740796909b5d011128b6c54954788d14faea9117"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
		$s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii

	condition:
		filesize <4KB and all of them
}
