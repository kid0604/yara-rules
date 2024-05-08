rule Windows_Trojan_SystemBC_c1b58c2f
{
	meta:
		author = "Elastic Security"
		id = "c1b58c2f-8bbf-4c03-9f53-13ab2fb081cc"
		fingerprint = "dfbf98554e7fb8660e4eebd6ad2fadc394fc2a4168050390370ec358f6af1c1d"
		creation_date = "2024-05-02"
		last_modified = "2024-05-08"
		threat_name = "Windows.Trojan.SystemBC"
		reference_sample = "016fc1db90d9d18fe25ed380606346ef12b886e1db0d80fe58c22da23f6d677d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SystemBC"
		filetype = "executable"

	strings:
		$a1 = "GET %s HTTP/1.0" ascii fullword
		$a2 = "HOST1:"
		$a3 = "PORT1:"
		$a4 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
		$a5 = "BEGINDATA" ascii fullword
		$a6 = "socks32.dll" ascii fullword

	condition:
		5 of them
}
