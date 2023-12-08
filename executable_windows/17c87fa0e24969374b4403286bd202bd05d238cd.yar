rule Windows_Trojan_Squirrelwaffle_d3b685a1
{
	meta:
		author = "Elastic Security"
		id = "d3b685a1-2d1c-44a3-8d83-ff661d491a52"
		fingerprint = "15df7efab9cc40ff57070d18ae67b549c55595d7cbf3ca02963336e4297156c4"
		creation_date = "2021-09-21"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Squirrelwaffle"
		reference_sample = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Squirrelwaffle"
		filetype = "executable"

	strings:
		$a1 = { 08 85 C0 75 0F 8D 45 94 50 8D 45 D0 6A 20 50 FF D7 83 C4 0C }

	condition:
		all of them
}
