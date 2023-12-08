rule webshell_php_cmd
{
	meta:
		description = "Web Shell - file cmd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if($_GET['cmd']) {" fullword
		$s1 = "// cmd.php = Command Execution" fullword
		$s7 = "  system($_GET['cmd']);" fullword

	condition:
		all of them
}
