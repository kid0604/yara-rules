rule Trojan_Win32_Plabit
{
	meta:
		author = "Microsoft"
		description = "Installer component"
		sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
		$str2 = "GetInstanceW"
		$str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

	condition:
		$str1 and $str2 and $str3
}
