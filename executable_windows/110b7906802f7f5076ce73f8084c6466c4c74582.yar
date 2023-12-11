rule Windows_Ransomware_Phobos_ff55774d : beta
{
	meta:
		author = "Elastic Security"
		id = "ff55774d-4425-4243-8156-ce029c1d5860"
		fingerprint = "d8016c9be4a8e5b5ac32b7108542fee8426d65b4d37e2a9c5ad57284abb3781e"
		creation_date = "2020-06-25"
		last_modified = "2021-08-23"
		description = "Identifies Phobos ransomware"
		threat_name = "Windows.Ransomware.Phobos"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = { 24 18 83 C4 0C 8B 4F 0C 03 C6 50 8D 54 24 18 52 51 6A 00 6A 00 89 44 }

	condition:
		1 of ($c*)
}
