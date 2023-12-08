import "pe"

rule APT_RU_APT27_HyperBro_Vftrace_Loader_Jan22_1
{
	meta:
		description = "Yara rule to detect first Hyperbro Loader Stage, often called vftrace.dll. Detects decoding function."
		author = "Bundesamt fuer Verfassungsschutz (modified by Florian Roth)"
		date = "2022-01-14"
		sharing = "TLP:WHITE"
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		hash1 = "333B52C2CFAC56B86EE9D54AEF4F0FF4144528917BC1AA1FE1613EFC2318339A"
		os = "windows"
		filetype = "executable"

	strings:
		$decoder_routine = { 8A ?? 41 10 00 00 8B ?? 28 ?? ?? 4? 3B ?? 72 ?? }

	condition:
		uint16(0)==0x5a4d and filesize <5MB and $decoder_routine and pe.exports("D_C_Support_SetD_File")
}
