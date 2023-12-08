rule Windows_Trojan_Hawkeye_975d546c
{
	meta:
		author = "Elastic Security"
		id = "975d546c-286b-4753-b894-d6ed0aa832f3"
		fingerprint = "5bbdb07fa6dd3e415f49d7f4fbc249c078ae42ebd81cad3015e32dfdc8f7cda6"
		creation_date = "2023-03-23"
		last_modified = "2023-04-23"
		threat_name = "Windows.Trojan.Hawkeye"
		reference_sample = "aca133bf1d72cf379101e6877871979d6e6e8bc4cc692a5ba815289735014340"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Hawkeye 975d546c"
		filetype = "executable"

	strings:
		$s1 = "api.telegram.org"
		$s2 = "Browsers/Passwords"
		$s3 = "Installed Browsers.txt"
		$s4 = "Browsers/AutoFills"
		$s5 = "Passwords.txt"
		$s6 = "System Information.txt"

	condition:
		all of them
}
