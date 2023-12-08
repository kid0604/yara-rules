rule Linux_Exploit_Local_a677fb9c
{
	meta:
		author = "Elastic Security"
		id = "a677fb9c-0271-4491-a7c7-48504b6ec389"
		fingerprint = "b7916eefad806131b39af5f9bef27648e2444c9a9c95216b520d73e64fa734f0"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "d20b260c7485173264e3e674adc7563ea3891224a3dc98bdd342ebac4a1349e8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 89 C0 89 45 EC 83 7D EC FF 75 1A 83 EC 0C 68 }

	condition:
		all of them
}
