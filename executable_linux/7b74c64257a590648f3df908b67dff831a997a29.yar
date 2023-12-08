rule Linux_Trojan_Dropperl_683c2ba1
{
	meta:
		author = "Elastic Security"
		id = "683c2ba1-fe4a-44e4-b176-8d5d5788e1a4"
		fingerprint = "42dcea472417140d0f7768e8189ac3a8a46aaeff039be1efd36f8d50f81e347c"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "a02e166fbf002dd4217c012f24bb3a8dbe310a9f0b0635eb20a7d315049367e1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}
