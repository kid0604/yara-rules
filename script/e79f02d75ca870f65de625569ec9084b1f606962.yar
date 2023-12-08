rule webshell_phpshell_2_1_config
{
	meta:
		description = "Web Shell - file config.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bd83144a649c5cc21ac41b505a36a8f3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword

	condition:
		all of them
}
