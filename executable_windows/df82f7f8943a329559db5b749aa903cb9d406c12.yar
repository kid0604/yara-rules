rule Windows_Trojan_Sliver_46525b49
{
	meta:
		author = "Elastic Security"
		id = "46525b49-f426-4ecb-9bd6-36752f0461e9"
		fingerprint = "104382f222b754b3de423803ac7be1d6fbdd9cbd11c855774d1ecb1ee73cb6c0"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Sliver"
		reference_sample = "ecce5071c28940a1098aca3124b3f82e0630c4453f4f32e1b91576aac357ac9c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Sliver (46525b49)"
		filetype = "executable"

	strings:
		$a1 = { B6 54 0C 48 0F B6 74 0C 38 31 D6 40 88 74 0C 38 48 FF C1 48 83 }
		$a2 = { 42 18 4C 8B 4A 20 48 8B 52 28 48 39 D9 73 51 48 89 94 24 C0 00 }

	condition:
		all of them
}
