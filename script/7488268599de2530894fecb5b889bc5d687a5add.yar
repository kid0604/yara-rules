rule CN_Honker_Webshell_PHP_php9
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cd3962b1dba9f1b389212e38857568b69ca76725"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii

	condition:
		filesize <1087KB and all of them
}
