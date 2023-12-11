rule Linux_Trojan_Kaiji_535f07ac
{
	meta:
		author = "Elastic Security"
		id = "535f07ac-d727-4866-aaed-74d297a1092c"
		fingerprint = "8853b2a1d5852e436cab2e3402a5ca13839b3cae6fbb56a74b047234b8c1233b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Kaiji"
		reference_sample = "28b2993d7c8c1d8dfce9cd2206b4a3971d0705fd797b9fde05211686297f6bb0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kaiji"
		filetype = "executable"

	strings:
		$a = { 44 24 10 48 8B 4C 24 08 48 83 7C 24 18 00 74 26 C6 44 24 57 00 48 8B 84 24 98 00 }

	condition:
		all of them
}
