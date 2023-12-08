rule Linux_Trojan_Mobidash_bb4f7f39
{
	meta:
		author = "Elastic Security"
		id = "bb4f7f39-1f1c-4a2d-a480-3e1d2b6967b7"
		fingerprint = "b7e96ff17a19ffcbfc87cdba3f86216271ff01c460ff7564f6af6b40c21a530b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { 75 1F 48 8D 64 24 08 48 89 DF 5B 48 89 EA 4C 89 E1 4C 89 EE 5D }

	condition:
		all of them
}
