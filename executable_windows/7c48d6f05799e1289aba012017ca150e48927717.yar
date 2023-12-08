rule Windows_Trojan_ServHelper_370c5287
{
	meta:
		author = "Elastic Security"
		id = "370c5287-0e2f-4113-95b6-53d31671fa46"
		fingerprint = "a66134e9344cc5ba403fe0aad70e8a991c61582d6a5640c3b9e4a554374176a2"
		creation_date = "2022-03-24"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.ServHelper"
		reference_sample = "05d183430a7afe16a3857fc4e87568fcc18518e108823c37eabf0514660aa17c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan ServHelper variant 370c5287"
		filetype = "executable"

	strings:
		$a = { 00 10 66 01 00 48 66 01 00 98 07 2B 00 50 66 01 00 95 66 01 }

	condition:
		all of them
}
