rule Linux_Trojan_BPFDoor_f690fe3b
{
	meta:
		author = "Elastic Security"
		id = "f690fe3b-1b3f-4101-931b-10932596f546"
		fingerprint = "504bfe57dcc3689881bdd0af55aab9a28dcd98e44b5a9255d2c60d9bc021130b"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan BPFDoor with fingerprint f690fe3b"
		filetype = "executable"

	strings:
		$a1 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 }

	condition:
		all of them
}
