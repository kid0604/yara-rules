rule Windows_Trojan_Trickbot_e7932501
{
	meta:
		author = "Elastic Security"
		id = "e7932501-66bf-4713-b10e-bcda29f4b901"
		fingerprint = "ae31b49266386a6cf42289a08da4a20fc1330096be1dae793de7b7230225bfc7"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant e7932501"
		filetype = "executable"

	strings:
		$a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }

	condition:
		all of them
}
