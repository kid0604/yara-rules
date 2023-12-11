rule Linux_Cryptominer_Generic_df937caa
{
	meta:
		author = "Elastic Security"
		id = "df937caa-ca6c-4a80-a68c-c265dab7c02c"
		fingerprint = "963642e141db6c55bd8251ede57b38792278ded736833564ae455cc553ab7d24"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 04 62 20 0A 10 02 0A 14 60 29 00 02 0C 24 14 60 7D 44 01 70 01 }

	condition:
		all of them
}
