rule Windows_Generic_MalCert_cd89378b
{
	meta:
		author = "Elastic Security"
		id = "cd89378b-1915-43b5-8dd1-063c8634c5ba"
		fingerprint = "18f77b670ba5e9f9e188f158ae3f0b586e850e956b73d024de0c18fb2cc48b68"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "763a4ca9f7ae1b026e87fe1336530edc308c5e23c4b3ef21741adc553eb4b106"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 65 98 E9 51 40 7E 30 11 49 D5 60 EA }

	condition:
		all of them
}
