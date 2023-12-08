import "pe"

rule EquationDrug_PlatformOrchestrator
{
	meta:
		description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "febc4f30786db7804008dc9bc1cebdc26993e240"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SERVICES.EXE" fullword wide
		$s1 = "\\command.com" fullword wide
		$s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s3 = "LSASS.EXE" fullword wide
		$s4 = "Windows Configuration Services" fullword wide
		$s8 = "unilay.dll" fullword ascii

	condition:
		all of them
}
