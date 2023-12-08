rule Windows_Trojan_GhostPulse_3fe1d02d
{
	meta:
		author = "Elastic Security"
		id = "3fe1d02d-5de3-42df-8389-6a55fc2b8afd"
		fingerprint = "18aed348ba64bee842fb6af3b3220e108052a67f49724cf34ba52c8ec7c15cac"
		creation_date = "2023-10-12"
		last_modified = "2023-10-26"
		threat_name = "Windows.Trojan.GhostPulse"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan GhostPulse"
		filetype = "executable"

	strings:
		$a = { 48 89 5C 24 08 48 89 7C 24 10 8B DA 45 33 D2 48 8B F9 41 2B D9 74 50 4C 8B D9 4C 2B C1 0F 1F 00 33 C9 }

	condition:
		all of them
}
