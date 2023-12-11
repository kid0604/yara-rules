rule webshell_spjspshell
{
	meta:
		description = "Web Shell - file spjspshell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d39d51154aaad4ba89947c459a729971"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"

	condition:
		all of them
}
