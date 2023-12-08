rule Linux_Trojan_Mobidash_601352dc
{
	meta:
		author = "Elastic Security"
		id = "601352dc-13b6-4c3f-a013-c54a50e46820"
		fingerprint = "acfca9259360641018d2bf9ba454fd5b65224361933557e007ab5cfb12186cd7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "5714e130075f4780e025fb3810f58a63e618659ac34d12abe211a1b6f2f80269"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { F6 74 14 48 8B BC 24 D0 00 00 00 48 8B 07 48 8B 80 B8 00 00 00 }

	condition:
		all of them
}
