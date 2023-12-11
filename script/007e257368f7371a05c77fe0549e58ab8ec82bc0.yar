rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_alt_1
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "@ini_set(\"highlight" fullword
		$s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
		$s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword

	condition:
		2 of them
}
