rule Windows_Generic_MalCert_e822d2d7
{
	meta:
		author = "Elastic Security"
		id = "e822d2d7-96fd-4aa6-8067-05a193e25df5"
		fingerprint = "66be1218888a8255047920a578918f25bce48f98d422032a81d9cde7f098ddac"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "1acfde9d39095bfb538c30f0523918bd1f2cae83f62009ec0a3a03d54e26d8ca"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 2A 07 4C F0 80 DF CB 55 86 83 23 83 }

	condition:
		all of them
}
