rule Linux_Cryptominer_Camelot_cdd631c1
{
	meta:
		author = "Elastic Security"
		id = "cdd631c1-2c03-47dd-b50a-e8c0b9f67271"
		fingerprint = "fa174ac25467ab6e0f11cf1f0a5c6bf653737e9bbdc9411aabeae460a33faa5e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "91549c171ae7f43c1a85a303be30169932a071b5c2b6cf3f4913f20073c97897"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot malware"
		filetype = "executable"

	strings:
		$a = { 00 5F 5A 4E 35 78 6D 72 69 67 35 50 6F 6F 6C 73 }

	condition:
		all of them
}
