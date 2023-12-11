rule Windows_Shellcode_Rdi_eee75d2c
{
	meta:
		author = "Elastic Security"
		id = "eee75d2c-78ef-460f-be96-4638443952fb"
		fingerprint = "2b8f840cecec00ce3112ea58e4e957e1b0754380e14a8fc8a39abc36feb077e9"
		creation_date = "2023-08-25"
		last_modified = "2023-11-02"
		threat_name = "Windows.Shellcode.Rdi"
		reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Shellcode Rdi"
		filetype = "executable"

	strings:
		$a = { 81 EC 14 01 00 00 53 55 56 57 6A 6B 58 6A 65 66 89 84 24 CC 00 00 00 33 ED 58 6A 72 59 6A 6E 5B 6A 6C 5A 6A 33 }

	condition:
		all of them
}
