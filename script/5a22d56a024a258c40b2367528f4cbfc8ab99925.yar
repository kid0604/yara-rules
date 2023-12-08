rule Test_php_php
{
	meta:
		description = "Semi-Auto-generated  - file Test.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "77e331abd03b6915c6c6c7fe999fcb50"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
		$s2 = "fwrite ($fp, \"$yazi\");" fullword
		$s3 = "$entry_line=\"HACKed by EntriKa\";" fullword

	condition:
		1 of them
}
