rule SimShell_1_0___Simorgh_Security_MGZ_php
{
	meta:
		description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "37cb1db26b1b0161a4bf678a6b4565bd"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Simorgh Security Magazine "
		$s1 = "Simshell.css"
		$s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
		$s3 = "www.simorgh-ev.com"

	condition:
		2 of them
}
