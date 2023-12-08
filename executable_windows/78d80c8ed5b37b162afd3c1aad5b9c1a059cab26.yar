rule Windows_Trojan_CobaltStrike_8751cdf9
{
	meta:
		author = "Elastic Security"
		id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
		fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
		creation_date = "2021-03-25"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}
