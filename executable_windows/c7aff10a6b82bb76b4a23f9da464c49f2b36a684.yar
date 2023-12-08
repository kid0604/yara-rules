rule Windows_Trojan_BloodAlchemy_c2d80609
{
	meta:
		author = "Elastic Security"
		id = "c2d80609-9a66-4fbb-b594-17d16372cb14"
		fingerprint = "8815e42ef85ae5a8915cd26b573cd7411c041778cdf4bc99efd45526e3699642"
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
		$a = { 55 8B EC 83 EC 30 53 56 57 33 C0 8D 7D F0 AB 33 DB 68 02 80 00 00 6A 40 89 5D FC AB AB FF 15 28 }

	condition:
		all of them
}
