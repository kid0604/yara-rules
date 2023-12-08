import "pe"

rule MetrowerksCodeWarriorv20GUI
{
	meta:
		author = "malware-lu"
		description = "Detects Metrowerks CodeWarrior v2.0 GUI malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 [2] 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 [12] E8 [2] 00 00 E8 [2] 00 00 E8 }

	condition:
		$a0
}
