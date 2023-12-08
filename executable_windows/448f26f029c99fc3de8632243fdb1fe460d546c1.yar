rule Trojan_Win32_Placisc2
{
	meta:
		author = "Microsoft"
		description = "Dipsind variant"
		original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
		unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
		$str2 = "VPLRXZHTU"
		$str3 = "%d) Command:%s"
		$str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

	condition:
		$str1 and $str2 and $str3 and $str4
}
