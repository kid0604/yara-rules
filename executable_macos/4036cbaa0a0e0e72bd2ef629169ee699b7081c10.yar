rule MacOS_Trojan_Metasploit_293bfea9
{
	meta:
		author = "Elastic Security"
		id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
		fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
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
		$a1 = "_webcam_get_frame" ascii fullword
		$a2 = "_get_process_info" ascii fullword
		$a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
		$a4 = "Dumping cert info:" ascii fullword

	condition:
		all of them
}
