rule Windows_Ransomware_Ryuk_25d3c5ba : beta
{
	meta:
		author = "Elastic Security"
		id = "25d3c5ba-8f80-4af0-8a5d-29c974fb016a"
		fingerprint = "18e70599e3a187e77697844fa358dd150e7e25ac74060e8c7cf2707fb7304efd"
		creation_date = "2020-04-30"
		last_modified = "2021-08-23"
		description = "Identifies RYUK ransomware"
		threat_name = "Windows.Ransomware.Ryuk"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }

	condition:
		1 of ($g*)
}
