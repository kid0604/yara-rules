rule webshell_webshell_123
{
	meta:
		description = "Web shells - generated from file webshell-123.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014-03-28"
		modified = "2023-01-27"
		score = 70
		hash = "2782bb170acaed3829ea9a04f0ac7218"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "// Web Shell!!" fullword
		$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
		$s3 = "$default_charset = \"UTF-8\";" fullword
		$s4 = "// url:http://www.weigongkai.com/shell/"

	condition:
		2 of them
}
