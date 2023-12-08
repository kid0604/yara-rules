rule Windows_Shellcode_Generic_f27d7beb
{
	meta:
		author = "Elastic Security"
		id = "f27d7beb-5ce0-4831-b1ad-320b346612c3"
		fingerprint = "3f8dd6733091ec229e1bebe9e4cd370ad47ab2e3678be4c2d9c450df731a6e5c"
		creation_date = "2022-06-08"
		last_modified = "2022-09-29"
		threat_name = "Windows.Shellcode.Generic"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows shellcode of generic type"
		filetype = "executable"

	strings:
		$a = { 53 48 89 E3 66 83 E4 00 48 B9 [8] BA 01 00 00 00 41 B8 00 00 00 00 48 B8 [8] FF D0 48 89 DC 5B C3 }

	condition:
		all of them
}
