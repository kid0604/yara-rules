rule Windows_Trojan_CobaltStrike_663fc95d
{
	meta:
		author = "Elastic Security"
		id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
		fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
		creation_date = "2021-04-01"
		last_modified = "2021-12-17"
		description = "Identifies CobaltStrike via unidentified function code"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }

	condition:
		all of them
}
