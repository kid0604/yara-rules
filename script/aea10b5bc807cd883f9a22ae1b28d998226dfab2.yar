rule webshell_php_alt_1
{
	meta:
		description = "Semi-Auto-generated  - file webshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e425241b928e992bde43dd65180a4894"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
		$s3 = "PHP Web Shell"

	condition:
		all of them
}
