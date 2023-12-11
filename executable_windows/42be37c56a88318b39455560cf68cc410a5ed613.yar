rule Windows_Trojan_CobaltStrike_b54b94ac
{
	meta:
		author = "Elastic Security"
		id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
		fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep obfuscation routine"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
		$a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
		$a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
		$a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
		$a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }

	condition:
		any of them
}
