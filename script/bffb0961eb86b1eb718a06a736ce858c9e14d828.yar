rule webshell_PHPJackal_v1_5
{
	meta:
		description = "Web Shell - file PHPJackal v1.5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d76dc20a4017191216a0315b7286056f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
		$s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"

	condition:
		all of them
}
