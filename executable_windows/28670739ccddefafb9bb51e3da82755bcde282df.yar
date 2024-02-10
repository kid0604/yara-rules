rule Windows_Generic_Threat_b7852ccf
{
	meta:
		author = "Elastic Security"
		id = "b7852ccf-ba11-44e2-95b9-eb92d6976e15"
		fingerprint = "f33ef7996bcb0422227b9481d85b3663fb0f13f1be01837b42ac0c5f0bcff781"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "5ac70fa959be4ee37c0c56f0dd04061a5fed78fcbde21b8449fc93e44a8c133a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 45 2B 34 2C 3D 43 4A 32 3A 24 40 2F 22 3E 3F 3C 24 44 }
		$a2 = { 67 6F 72 67 65 6F 75 73 68 6F 72 6E 79 }
		$a3 = { 62 6C 61 63 6B 20 68 61 69 72 75 6E 73 68 61 76 65 64 }

	condition:
		all of them
}
