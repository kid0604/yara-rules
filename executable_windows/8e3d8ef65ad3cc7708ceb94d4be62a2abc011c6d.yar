rule Windows_Generic_Threat_f45b3f09
{
	meta:
		author = "Elastic Security"
		id = "f45b3f09-4203-41f7-870e-d8ef5126c391"
		fingerprint = "dfa72e0780e895ab5aa2369a425c64144e9bd435e55d8a0fefbe08121ae31df5"
		creation_date = "2024-03-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "577f1dbd76030c7e44ed28c748551691d446e268189af94e1fa1545f06395178"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on fingerprint f45b3f09"
		filetype = "executable"

	strings:
		$a1 = { 28 33 ED 44 8B ED 48 89 6C 24 78 44 8B FD 48 89 AC 24 88 00 00 00 44 8B F5 44 8B E5 E8 43 04 00 00 48 8B F8 8D 75 01 ?? ?? ?? ?? ?? 66 39 07 75 1A 48 63 47 3C 48 8D 48 C0 }

	condition:
		all of them
}
