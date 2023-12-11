rule _nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
		hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash3 = "f3ca29b7999643507081caab926e2e74"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
		$s1 = "$ret = posix_kill($pid,$sig);" fullword
		$s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
		$s3 = "$i = $nixpasswd;" fullword

	condition:
		2 of them
}
