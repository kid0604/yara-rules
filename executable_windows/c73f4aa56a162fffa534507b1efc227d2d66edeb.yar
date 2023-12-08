rule Windows_Ransomware_Clop_606020e7 : beta
{
	meta:
		author = "Elastic Security"
		id = "606020e7-ce1a-4a48-b801-100fd22b3791"
		fingerprint = "5ec4e00ddf2cb1315ec7d62dd228eee0d9c15fafe4712933d42e868f83f13569"
		creation_date = "2020-05-03"
		last_modified = "2021-08-23"
		description = "Identifies CLOP ransomware in unpacked state"
		threat_name = "Windows.Ransomware.Clop"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = { B8 E1 83 0F 3E F7 E6 8B C6 C1 EA 04 8B CA C1 E1 05 03 CA }

	condition:
		1 of ($d*)
}
