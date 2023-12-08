rule Windows_Trojan_BloodAlchemy_63084eea
{
	meta:
		author = "Elastic Security"
		id = "63084eea-358b-4fb0-9668-3f40f0aae9e7"
		fingerprint = "3f6ef0425b846b2126263c590d984bc618ad61de91a9141160c2b804c585ff6d"
		creation_date = "2023-09-25"
		last_modified = "2023-09-25"
		threat_name = "Windows.Trojan.BloodAlchemy"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BloodAlchemy"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 83 EC 38 53 56 57 8B 75 08 8D 7D F0 33 C0 33 DB AB 89 5D C8 89 5D D0 89 5D D4 AB 89 5D }

	condition:
		all of them
}
