rule Linux_Trojan_Xorddos_1a562d3b
{
	meta:
		author = "Elastic Security"
		id = "1a562d3b-bc59-4cb7-9ac1-7a4a79232869"
		fingerprint = "e052e99f15f5a0f704c04cae412cf4b1f01a8ee6e4ce880aedc79cf5aee9631a"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }

	condition:
		all of them
}
