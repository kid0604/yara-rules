rule sql_php_php_alt_1
{
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
		$s2 = "http://rst.void.ru"
		$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"

	condition:
		1 of them
}
