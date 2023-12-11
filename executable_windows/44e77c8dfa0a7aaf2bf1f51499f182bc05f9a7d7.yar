rule lsadump
{
	meta:
		description = "LSA dump programe (bootkey/syskey) - pwdump and others"
		author = "Benjamin DELPY (gentilkiwi)"
		os = "windows"
		filetype = "executable"

	strings:
		$str_sam_inc = "\\Domains\\Account" ascii nocase
		$str_sam_exc = "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey = { 4b 53 53 4d [20-70] 05 00 01 00}

	condition:
		(($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey) and not uint16(0)==0x5a4d
}
