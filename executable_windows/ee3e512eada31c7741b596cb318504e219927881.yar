rule Windows_Trojan_BruteRatel_9b267f96
{
	meta:
		author = "Elastic Security"
		id = "9b267f96-11b3-48e6-9d38-ecfd72cb7e3e"
		fingerprint = "f20cbaf39dc68460a2612298a5df9efdf5bdb152159d38f4696aedf35862bbb6"
		creation_date = "2022-06-23"
		last_modified = "2022-07-18"
		threat_name = "Windows.Trojan.BruteRatel"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BruteRatel"
		filetype = "executable"

	strings:
		$a1 = "calAllocPH" ascii fullword
		$a2 = "lizeCritPH" ascii fullword
		$a3 = "BadgerPH" ascii fullword
		$a4 = "VirtualPPH" ascii fullword
		$a5 = "TerminatPH" ascii fullword
		$a6 = "ickCountPH" ascii fullword
		$a7 = "SeDebugPH" ascii fullword
		$b1 = { 50 48 B8 E2 6A 15 64 56 22 0D 7E 50 48 B8 18 2C 05 7F BB 78 D7 27 50 48 B8 C9 EC BC 3D 84 54 9A 62 50 48 B8 A1 E1 3C 4E AF 2B F6 B1 50 48 B8 2E E6 7B A0 94 CA 9D F0 50 48 B8 61 52 80 AA 1A B6 4B 0E 50 48 B8 B2 13 11 5A 28 81 ED 60 50 48 B8 20 DE A9 34 89 08 C8 32 50 48 B8 9B DC C1 FF 79 CE 5B F5 50 48 B8 FD 57 3F 4C C7 D3 7A 21 50 48 B8 70 B8 63 0F AB 19 BF 1C 50 48 B8 48 F2 1B 72 1E 2A C6 8A 50 48 B8 E3 FA 38 E9 1D 76 E0 6F 50 48 B8 97 AD 75 }

	condition:
		3 of ($a*) or 1 of ($b*)
}
