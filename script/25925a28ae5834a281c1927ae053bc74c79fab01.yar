rule Antichat_Shell_v1_3_php
{
	meta:
		description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "40d0abceba125868be7f3f990f031521"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Antichat"
		$s1 = "Can't open file, permission denide"
		$s2 = "$ra44"

	condition:
		2 of them
}
