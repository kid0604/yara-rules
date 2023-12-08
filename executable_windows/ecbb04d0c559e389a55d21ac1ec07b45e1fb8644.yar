rule Windows_Ransomware_Ryuk_1a4ad952 : beta
{
	meta:
		author = "Elastic Security"
		id = "1a4ad952-cc99-4653-932b-290381e7c871"
		fingerprint = "d8c5162850e758e27439e808e914df63f42756c0b8f7c2b5f9346c0731d3960c"
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
		$e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }

	condition:
		1 of ($e*)
}
