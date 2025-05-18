rule Windows_Generic_MalCert_ff00d21d
{
	meta:
		author = "Elastic Security"
		id = "ff00d21d-632f-4a9f-81de-f07d54181156"
		fingerprint = "6ef1037539351e1af3b44235117dab4a15917a5ba0fa23a7ca9b45c354a953be"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "f275e6b5ded3553648a1f231cd4079d30186583be0edeca734b639073ae53854"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 04 4C 17 7A 97 }
		$a2 = "Netgear Inc."

	condition:
		all of them
}
