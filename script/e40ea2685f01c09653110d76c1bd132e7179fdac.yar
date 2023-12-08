rule backdoor1_php
{
	meta:
		description = "Semi-Auto-generated  - file backdoor1.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e1adda1f866367f52de001257b4d6c98"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
		$s2 = "class backdoor {"
		$s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"

	condition:
		1 of them
}
