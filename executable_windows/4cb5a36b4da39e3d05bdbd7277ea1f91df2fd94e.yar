import "pe"

rule MetrowerksCodeWarriorv20Console
{
	meta:
		author = "malware-lu"
		description = "Detects Metrowerks CodeWarrior v2.0 Console malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 [4] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 [4] E8 [12] E8 [2] 00 00 E8 [2] 00 00 E8 }

	condition:
		$a0
}
