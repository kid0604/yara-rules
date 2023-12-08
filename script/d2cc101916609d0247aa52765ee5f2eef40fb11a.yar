rule webshell_ironshell
{
	meta:
		description = "Web Shell - file ironshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
		$s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"

	condition:
		all of them
}
