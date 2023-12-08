rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "c99ftpbrutecheck"
		$s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
		$s2 = "$fqb_lenght = $nixpwdperpage;" fullword
		$s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword

	condition:
		2 of them
}
