rule Trojan_Win32_Plagon
{
	meta:
		author = "Microsoft"
		description = "Dipsind variant"
		original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
		unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "VPLRXZHTU"
		$str2 = {64 6F 67 32 6A 7E 6C}
		$str3 = "Dqpqftk(Wou\"Isztk)"
		$str4 = "StartThreadAtWinLogon"

	condition:
		$str1 and $str2 and $str3 and $str4
}
