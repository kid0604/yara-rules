rule Linux_Trojan_Xorddos_073e6161
{
	meta:
		author = "Elastic Security"
		id = "073e6161-35a3-4e5e-a310-8cc50cb28edf"
		fingerprint = "12d04597fd60ed143a1b256889eefee1f5a8c77f4f300e72743e3cfa98ba8e99"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }

	condition:
		all of them
}
