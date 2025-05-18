rule Windows_Generic_MalCert_2a46688e
{
	meta:
		author = "Elastic Security"
		id = "2a46688e-de35-4db3-b387-57449a85085b"
		fingerprint = "62fc9201fcca418c8574dcdb8723a3d6661450db088f1da5f1ffa9128910f27d"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "d2ed769550844ef52eb6d7b0c8617451076504f823e410ab26ec146dc379935c"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 21 52 17 A2 A5 CD 73 2C CE FE 5F 88 }

	condition:
		all of them
}
