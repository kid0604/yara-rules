rule Windows_Ransomware_Ryuk_72b5fd9d : beta
{
	meta:
		author = "Elastic Security"
		id = "72b5fd9d-23db-4f18-88d9-a849ec039135"
		fingerprint = "7c394aa283336013b74a8aaeb56e8363033958b4a1bd8011f3b32cfe2d37e088"
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
		$d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }

	condition:
		1 of ($d*)
}
