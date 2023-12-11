rule Trojan_Win32_Plaklog
{
	meta:
		author = "Microsoft"
		description = "Hook-based keylogger"
		original_sample_sha1 = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
		unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "++[%s^^unknown^^%s]++"
		$str2 = "vtfs43/emm"
		$str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

	condition:
		$str1 and $str2 and $str3
}
