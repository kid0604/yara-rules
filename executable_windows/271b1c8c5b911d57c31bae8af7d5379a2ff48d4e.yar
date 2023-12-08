rule win_rhadhamanthys_shellcode_feb_2023
{
	meta:
		author = "Embee_Research @ Huntress Labs"
		created = "2023/02/24"
		reference_sample = "c1f0d2e7b5f3cbdde3a9b61e4fe8aa9ddff6311103ede6771a030b837ecd18e2"
		description = "Detects Rhadamanthys shellcode in Windows executables"
		os = "windows"
		filetype = "executable"

	strings:
		$hashing = {8b f0 c1 e6 13 c1 e8 0d 0b f0 0f be c1 8a 4a 01 03 c6 42}
		$shellcode = {E8 ?? 00 [2-10] 90 90 90 }

	condition:
		all of them
}
