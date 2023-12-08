rule Windows_Trojan_CobaltStrike_29374056
{
	meta:
		author = "Elastic Security"
		id = "29374056-03ce-484b-8b2d-fbf75be86e27"
		fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike MZ Reflective Loader."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
		$a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }

	condition:
		1 of ($a*)
}
