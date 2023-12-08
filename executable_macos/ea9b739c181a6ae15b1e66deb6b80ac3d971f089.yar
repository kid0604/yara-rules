rule MacOS_Trojan_Metasploit_6cab0ec0
{
	meta:
		author = "Elastic Security"
		id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
		fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Metasploit"
		reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Metasploit"
		filetype = "executable"

	strings:
		$a = "mettlesploit! " ascii fullword

	condition:
		all of them
}
