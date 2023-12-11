rule Linux_Trojan_Winnti_de4b0f6e
{
	meta:
		author = "Elastic Security"
		id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
		fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Winnti"
		reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Winnti"
		filetype = "executable"

	strings:
		$a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }

	condition:
		all of them
}
