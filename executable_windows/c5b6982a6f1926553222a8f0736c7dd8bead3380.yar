rule Windows_Generic_Threat_5c18a7f9
{
	meta:
		author = "Elastic Security"
		id = "5c18a7f9-01af-468b-9a63-cfecbeb739d7"
		fingerprint = "68c9114ac342d527cf6f0cea96b63dfeb8e5d80060572fad2bbc7d287c752d4a"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fd272678098eae8f5ec8428cf25d2f1d8b65566c59e363d42c7ce9ffab90faaa"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 5D E9 CD 1A 00 00 8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 03 1B 00 00 59 C9 C3 8B FF 55 8B EC 51 56 57 E8 6B 18 00 00 8B F0 85 F6 74 1C 8B 16 8B CA 8D 82 90 00 00 }

	condition:
		all of them
}
