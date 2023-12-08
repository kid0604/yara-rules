rule Windows_Trojan_Metasploit_4a1c4da8
{
	meta:
		author = "Elastic Security"
		id = "4a1c4da8-837d-4ad1-a672-ddb8ba074936"
		fingerprint = "7a31ce858215f0a8732ce6314bfdbc3975f1321e3f87d7f4dc5a525f15766987"
		creation_date = "2021-06-10"
		last_modified = "2021-08-23"
		description = "Identifies Metasploit 64 bit reverse tcp shellcode."
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "9582d37ed9de522472abe615dedef69282a40cfd58185813c1215249c24bbf22"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 6A 10 56 57 68 99 A5 74 61 FF D5 85 C0 74 0A FF 4E 08 }

	condition:
		all of them
}
