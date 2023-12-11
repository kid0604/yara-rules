rule Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php
{
	meta:
		description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "49ad9117c96419c35987aaa7e2230f63"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
		$s1 = "Mode Shell v1.0</font></span>"
		$s2 = "has been already loaded. PHP Emperor <xb5@hotmail."

	condition:
		1 of them
}
