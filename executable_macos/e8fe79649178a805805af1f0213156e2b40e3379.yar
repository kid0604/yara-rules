rule MacOS_Trojan_Metasploit_448fa81d
{
	meta:
		author = "Elastic Security"
		id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
		fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Metasploit"
		reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Metasploit variant 448fa81d"
		filetype = "executable"

	strings:
		$a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
		$a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
		$a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword

	condition:
		any of them
}
