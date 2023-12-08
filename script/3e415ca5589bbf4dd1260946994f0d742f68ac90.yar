rule FSO_s_test
{
	meta:
		description = "Webshells Auto-generated - file test.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "82cf7b48da8286e644f575b039a99c26"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"

	condition:
		all of them
}
