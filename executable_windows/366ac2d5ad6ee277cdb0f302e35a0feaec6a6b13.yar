rule Windows_Trojan_Trickbot_91516cf4
{
	meta:
		author = "Elastic Security"
		id = "91516cf4-c826-4d5d-908f-e1c0b3bccec5"
		fingerprint = "2667c7181fb4db3f5765369fc2ec010b807a7bf6e2878fc42af410f036c61cbe"
		creation_date = "2021-03-30"
		last_modified = "2021-08-31"
		description = "Generic signature used to identify Trickbot module usage"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "6cd0d4666553fd7184895502d48c960294307d57be722ebb2188b004fc1a8066"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<moduleconfig>" ascii wide
		$a2 = "<autostart>" ascii wide
		$a3 = "</autostart>" ascii wide
		$a4 = "</moduleconfig>" ascii wide

	condition:
		all of them
}
