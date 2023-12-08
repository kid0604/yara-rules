rule shell_php_php_alt_1
{
	meta:
		description = "Semi-Auto-generated  - file shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1a95f0163b6dea771da1694de13a3d8d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
		$s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
		$s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword

	condition:
		1 of them
}
