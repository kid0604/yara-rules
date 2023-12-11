rule Linux_Webshell_Generic_e80ff633
{
	meta:
		author = "Elastic Security"
		id = "e80ff633-990e-4e2e-ac80-2e61685ab8b0"
		fingerprint = "dcca52dce2d50b0aa6cf0132348ce9dc234b985ae683b896d9971d409f109849"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Webshell.Generic"
		reference_sample = "7640ba6f2417931ef901044152d5bfe1b266219d13b5983d92ddbdf644de5818"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux webshells"
		filetype = "script"

	strings:
		$a = { 24 A8 00 00 00 89 1C 24 83 3C 24 00 74 23 83 04 24 24 8D B4 24 AC 00 }

	condition:
		all of them
}
