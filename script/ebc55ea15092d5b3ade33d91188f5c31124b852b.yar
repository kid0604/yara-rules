rule _1_c2007_php_php_c100_php
{
	meta:
		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash1 = "d089e7168373a0634e1ac18c0ee00085"
		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
		$s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"

	condition:
		1 of them
}
