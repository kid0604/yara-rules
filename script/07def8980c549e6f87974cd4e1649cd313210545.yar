rule webshell_Private_i3lue
{
	meta:
		description = "Web Shell - file Private-i3lue.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"

	condition:
		all of them
}
