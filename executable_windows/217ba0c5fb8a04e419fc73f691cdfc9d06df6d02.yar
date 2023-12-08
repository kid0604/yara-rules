rule Trojan_Win32_PlaLsaLog
{
	meta:
		author = "Microsoft"
		description = "Loader / possible incomplete LSA Password Filter"
		original_sample_sha1 = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
		unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
		$str2 = "PasswordChangeNotify"

	condition:
		$str1 and $str2
}
