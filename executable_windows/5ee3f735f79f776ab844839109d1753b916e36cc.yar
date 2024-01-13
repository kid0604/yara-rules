rule Windows_Generic_Threat_0350ed31
{
	meta:
		author = "Elastic Security"
		id = "0350ed31-ed07-4e9a-8488-3765c990f25c"
		fingerprint = "aac41abf60a16c02c6250c0468c6f707f9771b48da9e78633de7141d09ca23c8"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 35 6A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 3F }

	condition:
		all of them
}
