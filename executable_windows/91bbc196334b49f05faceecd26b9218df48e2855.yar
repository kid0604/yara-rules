rule Windows_Ransomware_Clop_6a1670aa : beta
{
	meta:
		author = "Elastic Security"
		id = "6a1670aa-7f78-455b-9e28-f39ed4c6476e"
		fingerprint = "7c24cc6a519922635a519dad412d1a07728317b91f90a120ccc1c7e7e2c8a002"
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
		$b1 = { FF 15 04 E1 40 00 83 F8 03 74 0A 83 F8 02 }

	condition:
		1 of ($b*)
}
