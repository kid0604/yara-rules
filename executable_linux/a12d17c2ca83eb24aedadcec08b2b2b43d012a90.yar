rule Linux_Exploit_Race_758a0884
{
	meta:
		author = "Elastic Security"
		id = "758a0884-0174-46c8-a57a-980fc04360d0"
		fingerprint = "3516086ae773ec1c1de75a54bafbb72ad49b4c7f1661961d5613462b53f26c43"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Race"
		reference_sample = "a4966baaa34b05cb782071ef114a53cac164e6dece275c862fe96a2cff4a6f06"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit race"
		filetype = "executable"

	strings:
		$a = { 00 22 00 00 00 36 00 00 00 18 85 04 08 34 00 00 00 12 00 00 }

	condition:
		all of them
}
