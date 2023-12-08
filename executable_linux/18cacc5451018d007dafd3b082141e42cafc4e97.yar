rule Linux_Trojan_Ddostf_dc47a873
{
	meta:
		author = "Elastic Security"
		id = "dc47a873-65a0-430d-a598-95be7134f207"
		fingerprint = "f103490a9dedc0197f50ca2b412cf18d2749c8d6025fd557f1686bc38f32db52"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ddostf"
		reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ddostf"
		filetype = "executable"

	strings:
		$a = { 05 88 10 8B 45 08 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 08 C6 40 }

	condition:
		all of them
}
