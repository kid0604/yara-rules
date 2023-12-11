rule Windows_Exploit_Dcom_7a1bcec7
{
	meta:
		author = "Elastic Security"
		id = "7a1bcec7-e177-4adf-97a7-0d876bf65abc"
		fingerprint = "0abae84599e490056412d5a5ce1868ea118551243377d59cbb6ebd83701769b8"
		creation_date = "2021-01-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Exploit.Dcom"
		reference_sample = "84073caf71d0e0523adeb96169c85b8f0bfea09e7ef3bf677bfc19d3b536d8a5"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows DCOM exploit"
		filetype = "executable"

	strings:
		$a = { 20 62 79 20 46 6C 61 73 68 53 6B 79 20 61 6E 64 20 42 65 6E }

	condition:
		all of them
}
