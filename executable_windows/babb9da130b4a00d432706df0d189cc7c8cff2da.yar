rule Windows_Generic_MalCert_7bfcc952
{
	meta:
		author = "Elastic Security"
		id = "7bfcc952-8243-4199-bbce-f904a397220d"
		fingerprint = "bdf093a252f2a7e0313bc42db4297d84017ea35003a8c3673c092565d9356ce1"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "4b264458f5383fdaab253b68eefaeee23de9702f12f1fbb0454d80b72692b5b5"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 08 D2 A6 70 58 24 F5 5C 15 BF 66 C6 7D B5 23 A9 }

	condition:
		all of them
}
