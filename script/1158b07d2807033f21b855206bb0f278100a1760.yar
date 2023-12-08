rule _c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php
{
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash3 = "d089e7168373a0634e1ac18c0ee00085"
		hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword

	condition:
		all of them
}
