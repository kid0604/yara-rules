rule Linux_Hacktool_Flooder_d90c4cbe
{
	meta:
		author = "Elastic Security"
		id = "d90c4cbe-4d0a-4341-a58b-a472b67282d6"
		fingerprint = "64796aa7faa2e945b5c856c1c913cb62175413dc1df88505dececcfbd2878cb1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 89 D8 F7 D0 5B 5D C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 89 }

	condition:
		all of them
}
