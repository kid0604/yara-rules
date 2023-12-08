rule Linux_Trojan_Mobidash_494d5b0f
{
	meta:
		author = "Elastic Security"
		id = "494d5b0f-09c7-4fcb-90e9-1efc57c45082"
		fingerprint = "e3316257592dc9654a5e63cf33c862ea1298af7a893e9175e1a15c7aaa595f6a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "7e08df5279f4d22f1f27553946b0dadd60bb8242d522a8dceb45ab7636433c2f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash variant with ID 494d5b0f"
		filetype = "executable"

	strings:
		$a = { 00 18 00 00 00 40 04 00 00 01 5B 00 00 00 3A 00 00 00 54 04 00 00 05 A1 00 }

	condition:
		all of them
}
