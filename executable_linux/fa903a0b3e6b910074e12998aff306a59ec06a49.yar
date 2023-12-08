rule Linux_Trojan_Xorddos_bef22375
{
	meta:
		author = "Elastic Security"
		id = "bef22375-0a71-4f5b-bfd1-e2e718b5c36f"
		fingerprint = "0128e8725a0949dd23c23addc1158d28c334cfb040aad2b8f8d58f39720c41ef"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }

	condition:
		all of them
}
