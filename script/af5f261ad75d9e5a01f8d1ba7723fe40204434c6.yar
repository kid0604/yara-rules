rule webshell_PHP_bug_1_
{
	meta:
		description = "Web Shell - file bug (1).php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "@include($_GET['bug']);" fullword

	condition:
		all of them
}
