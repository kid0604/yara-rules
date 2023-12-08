rule Windows_Trojan_Bazar_9dddea36
{
	meta:
		author = "Elastic Security"
		id = "9dddea36-1345-434b-8ce6-54d2eab39616"
		fingerprint = "e322e36006cc017d5d5d9887c89b180c5070dbe5a9efd9fb7ae15cda5b726d6c"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Bazar"
		reference_sample = "63df43daa61f9a0fbea2e5409b8f0063f7af3363b6bc8d6984ce7e90c264727d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Bazar"
		filetype = "executable"

	strings:
		$a = { C4 10 5B 5F 5E C3 41 56 56 57 55 53 48 83 EC 18 48 89 C8 48 }

	condition:
		all of them
}
