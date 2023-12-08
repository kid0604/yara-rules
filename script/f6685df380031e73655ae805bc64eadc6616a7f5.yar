rule webshell_alt_1
{
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f2f8c02921f29368234bfb4d4622ad19"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "RhViRYOzz"
		$s1 = "d\\O!jWW"
		$s2 = "bc!jWW"
		$s3 = "0W[&{l"
		$s4 = "[INhQ@\\"

	condition:
		all of them
}
