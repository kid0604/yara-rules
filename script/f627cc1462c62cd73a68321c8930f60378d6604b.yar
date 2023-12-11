rule webshell_Ani_Shell
{
	meta:
		description = "Web Shell - file Ani-Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "889bfc9fbb8ee7832044fc575324d01a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$Python_CODE = \"I"
		$s6 = "$passwordPrompt = \"\\n================================================="
		$s7 = "fputs ($sockfd ,\"\\n==============================================="

	condition:
		1 of them
}
