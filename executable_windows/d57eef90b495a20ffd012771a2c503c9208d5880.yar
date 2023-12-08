rule Windows_Backdoor_Goldbackdoor_f11d57df
{
	meta:
		author = "Elastic Security"
		id = "f11d57df-8dd4-481c-a557-f83ae05d53fe"
		fingerprint = "fed0317d43910d962908604812c2cd1aff6e67f7e245c82b39f2ac6dc14b6edb"
		creation_date = "2022-04-29"
		last_modified = "2022-06-09"
		threat_name = "Windows.Backdoor.Goldbackdoor"
		reference_sample = "45ece107409194f5f1ec2fbd902d041f055a914e664f8ed2aa1f90e223339039"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Backdoor.Goldbackdoor"
		filetype = "executable"

	strings:
		$a = { C7 45 ?? 64 69 72 25 C7 45 ?? 5C 53 79 73 C7 45 ?? 74 65 6D 33 C7 45 ?? 32 5C 00 00 C7 45 ?? 2A 2E 65 78 C7 45 ?? 65 00 00 00 E8 ?? ?? ?? ?? FF D0 }
		$b = { B9 18 48 24 9D E8 ?? ?? ?? ?? FF D0 }
		$c = { B9 F8 92 FA 98 E8 ?? ?? ?? ?? FF D0 }
		$a1 = { 64 A1 30 00 00 00 53 55 56 }
		$b1 = { B9 76 DB 7A AA 6A 40 68 00 30 00 00 FF 75 ?? 50 E8 ?? ?? ?? ?? FF D0 }
		$c1 = { B9 91 51 13 EE 50 68 80 00 00 00 6A 04 50 50 ?? ?? ?? ?? ?? ?? ?? 6A 04 50 E8 ?? ?? ?? ?? FF D0 }

	condition:
		all of them
}
