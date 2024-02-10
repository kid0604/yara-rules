rule Windows_Trojan_DarkGate_07ef6f14
{
	meta:
		author = "Elastic Security"
		id = "07ef6f14-4eb5-4c15-94af-117c68106104"
		fingerprint = "fd0aab53bddd3872147aa064a571d118cc00a6643d72c017fe26f6e0d19288e1"
		creation_date = "2023-12-14"
		last_modified = "2024-02-08"
		threat_name = "Windows.Trojan.DarkGate"
		reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan DarkGate variant 07ef6f14"
		filetype = "executable"

	strings:
		$binary0 = { 8B 04 24 0F B6 44 18 FF 33 F8 43 4E }
		$binary1 = { 8B D7 32 54 1D FF F6 D2 88 54 18 FF 43 4E }

	condition:
		all of them
}
