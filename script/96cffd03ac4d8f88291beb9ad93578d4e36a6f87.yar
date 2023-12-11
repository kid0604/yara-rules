rule _w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php
{
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
		$s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
		$s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"

	condition:
		1 of them
}
