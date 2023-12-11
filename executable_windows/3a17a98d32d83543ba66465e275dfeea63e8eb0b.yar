rule Windows_Ransomware_Phobos_11ea7be5 : beta
{
	meta:
		author = "Elastic Security"
		id = "11ea7be5-7aac-41d7-8d09-45131a9c656e"
		fingerprint = "a264f93e085134e5114c5d72e1bf93e70935e33756a79f1021e9c1e71d6c8697"
		creation_date = "2020-06-25"
		last_modified = "2021-08-23"
		description = "Identifies Phobos ransomware"
		threat_name = "Windows.Ransomware.Phobos"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = { C0 74 30 33 C0 40 8B CE D3 E0 85 C7 74 19 66 8B 04 73 66 89 }

	condition:
		1 of ($b*)
}
