rule Windows_Generic_MalCert_58979ccd
{
	meta:
		author = "Elastic Security"
		id = "58979ccd-b83e-4708-b84f-314bbc26f103"
		fingerprint = "e40ea37edb795ef835748eb15d4eb5c66b8f80771ccbd197a7ee3df4520344de"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "12bf973b503296da400fd6f9e3a4c688f14d56ce82ffcfa9edddd7e4b6b93ba9"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 21 40 69 1D DE 2D 71 48 85 84 15 D5 }

	condition:
		all of them
}
