rule Windows_Generic_Threat_45d1e986
{
	meta:
		author = "Elastic Security"
		id = "45d1e986-78fb-4a83-97f6-2b40c657e709"
		fingerprint = "facb67b78cc4d6cf5d141fd7153d331209e5ce46f29c0078c7e5683165c37057"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 45 00 06 00 00 00 08 28 45 00 09 00 00 00 14 28 45 00 09 00 00 00 20 28 45 00 07 00 00 00 28 28 45 00 0A 00 00 00 34 28 45 00 0B 00 00 00 40 28 45 00 09 00 00 00 5B 81 45 00 00 00 00 00 4C }

	condition:
		all of them
}
