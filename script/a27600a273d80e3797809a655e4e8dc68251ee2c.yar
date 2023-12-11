rule webshell_s72_Shell_v1_1_Coding
{
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c2e8346a5515c81797af36e7e4a3828e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "

	condition:
		all of them
}
