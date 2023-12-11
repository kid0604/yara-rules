rule Linux_Trojan_Tsunami_0a028640
{
	meta:
		author = "Elastic Security"
		id = "0a028640-581f-4183-9313-e36c5812e217"
		fingerprint = "1b296e8baffbe3e0e49aee23632afbfab75147f31561d73eb0c82f909c5ec718"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "e36081f0dbd6d523c9378cdd312e117642b0359b545b29a61d8f9027d8c0f2f0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Tsunami malware"
		filetype = "executable"

	strings:
		$a = { 10 85 C0 74 2D 8B 45 0C 0F B6 00 84 C0 74 19 8B 45 0C 83 C0 01 83 }

	condition:
		all of them
}
