rule Trojan_Win32_Plainst
{
	meta:
		author = "Microsoft"
		description = "Installer component"
		original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
		unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
		$str2 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

	condition:
		$str1 and $str2
}
