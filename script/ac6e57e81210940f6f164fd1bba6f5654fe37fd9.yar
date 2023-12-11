rule Webshell_Tiny_JSP_2
{
	meta:
		description = "Detects a tiny webshell - chine chopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-12-05"
		score = 100
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<%eval(Request(" nocase

	condition:
		uint16(0)==0x253c and filesize <40 and all of them
}
