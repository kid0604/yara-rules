rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
		$s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"

	condition:
		1 of them
}
