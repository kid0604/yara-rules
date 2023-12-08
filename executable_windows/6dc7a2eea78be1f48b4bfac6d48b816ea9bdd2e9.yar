rule Trojan_Win32_Adupib
{
	meta:
		author = "Microsoft"
		description = "Adupib SSL Backdoor"
		original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
		unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "POLL_RATE"
		$str2 = "OP_TIME(end hour)"
		$str3 = "%d:TCP:*:Enabled"
		$str4 = "%s[PwFF_cfg%d]"
		$str5 = "Fake_GetDlgItemTextW: ***value***="

	condition:
		$str1 and $str2 and $str3 and $str4 and $str5
}
