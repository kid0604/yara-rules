rule Trojan_Win32_Dipsind_B
{
	meta:
		author = "Microsoft"
		description = "Dipsind Family"
		sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
		$frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
		$frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

	condition:
		$frg1 and $frg2 and $frg3
}
