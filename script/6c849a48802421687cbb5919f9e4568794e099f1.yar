rule _c99shell_v1_0_php_php_c99php_SsEs_php_php_alt_1
{
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword

	condition:
		1 of them
}
