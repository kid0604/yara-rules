rule Windows_Trojan_Trickbot_32930807
{
	meta:
		author = "Elastic Security"
		id = "32930807-30bb-4c57-8e17-0da99a816405"
		fingerprint = "0aeb68977f4926272f27d5fba44e66bdbb9d6a113da5d7b4133a379b06df4474"
		creation_date = "2021-03-30"
		last_modified = "2021-10-04"
		description = "Targets cookiesdll.dll module containing functionality used to retrieve browser cookie data"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "e999b83629355ec7ff3b6fda465ef53ce6992c9327344fbf124f7eb37808389d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
		$a2 = "Cookies send failure: servers unavailable" ascii fullword
		$a3 = "<moduleconfig>"

	condition:
		all of them
}
