rule phvayvv_php_php
{
	meta:
		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "35fb37f3c806718545d97c6559abd262"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
		$s1 = "$baglan=fopen($duzkaydet,'w');"
		$s2 = "PHVayv 1.0"

	condition:
		1 of them
}
