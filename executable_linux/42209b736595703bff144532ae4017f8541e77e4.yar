rule Linux_Exploit_Local_6229602f
{
	meta:
		author = "Elastic Security"
		id = "6229602f-1c88-46fa-8fae-a6268ed6d632"
		fingerprint = "b26b21518fd436d79d6a23dbf3d7056b7c056e4df6639718e285de096476f61d"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "4fdb15663a405f6fc4379aad9a5021040d7063b8bb82403bedb9578d45d428fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 89 C0 89 45 FC 83 7D FC 00 7D 17 68 ?? ?? 04 08 }

	condition:
		all of them
}
