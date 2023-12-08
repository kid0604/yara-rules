rule Windows_Trojan_CobaltStrike_d00573a3
{
	meta:
		author = "Elastic Security"
		id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
		fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Screenshot module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "screenshot.x64.dll" ascii fullword
		$a2 = "screenshot.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\screenshot" ascii fullword
		$b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
		$b2 = "GetDesktopWindow" ascii fullword
		$b3 = "CreateCompatibleBitmap" ascii fullword
		$b4 = "GDI32.dll" ascii fullword
		$b5 = "ReflectiveLoader"
		$b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword

	condition:
		2 of ($a*) or 5 of ($b*)
}
