rule Windows_Trojan_RedLineStealer_6dfafd7b
{
	meta:
		author = "Elastic Security"
		id = "6dfafd7b-5188-4ec7-9ba4-58b8f05458e5"
		fingerprint = "b7770492fc26ada1e5cb5581221f59b1426332e57eb5e04922f65c25b92ad860"
		creation_date = "2024-01-05"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }

	condition:
		all of them
}
