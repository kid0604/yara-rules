rule c99madshell_v2_0_php_php
{
	meta:
		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d27292895da9afa5b60b9d3014f39294"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"

	condition:
		all of them
}
