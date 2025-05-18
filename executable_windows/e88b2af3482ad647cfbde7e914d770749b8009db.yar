rule Windows_Generic_MalCert_ea0f93ba
{
	meta:
		author = "Elastic Security"
		id = "ea0f93ba-c140-4684-a07d-ef16e70a625c"
		fingerprint = "d75056b8912163520ceeba6ea328a9bf203a1d1b5690fcc0ed30903f23c9f632"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "8143a7df9e65ecc19d5f5e19cdb210675fa16a940382c053724420f2bae4c8bd"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 4D B8 E2 54 19 B9 6C 60 FE E8 65 C7 01 B6 2D EF }

	condition:
		all of them
}
