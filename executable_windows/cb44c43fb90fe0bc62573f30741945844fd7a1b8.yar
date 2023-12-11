rule Windows_Trojan_Generic_a160ca52
{
	meta:
		author = "Elastic Security"
		id = "a160ca52-8911-4649-a1fa-ac8f6f75e18d"
		fingerprint = "06eca9064ca27784b61994844850f05c47c07ba6c4242a2572d6d0c484a920f0"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "650bf19e73ac2d9ebbf62f15eeb603c2b4a6a65432c70b87edc429165d6706f3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = { 1C 85 C9 74 02 8B 09 8D 41 FF 89 45 F0 89 55 EC 8B 55 EC 8B }

	condition:
		all of them
}
