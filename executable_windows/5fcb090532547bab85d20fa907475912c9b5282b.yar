import "pe"

rule APT_Turla_Agent_BTZ_Gen_1
{
	meta:
		description = "Detects Turla Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-06-16"
		score = 80
		hash1 = "c905f2dec79ccab115ad32578384008696ebab02276f49f12465dcd026c1a615"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
		$s1 = "release mutex - %u (%u)(%u)" fullword ascii
		$s2 = "\\system32\\win.com" ascii
		$s3 = "Command Id:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
		$s4 = "MakeFile Error(%d) copy file to temp file %s" fullword ascii
		$s5 = "%s%%s08x.tmp" fullword ascii
		$s6 = "Run instruction: %d ID:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
		$s7 = "Mutex_Log" fullword ascii
		$s8 = "%s\\system32\\winview.ocx" fullword ascii
		$s9 = "Microsoft(R) Windows (R) Operating System" fullword wide
		$s10 = "Error: pos(%d) > CmdSize(%d)" fullword ascii
		$s11 = "\\win.com" ascii
		$s12 = "Error(%d) run %s " fullword ascii
		$s13 = "%02d.%02d.%04d Log begin:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="9d0d6daa47d6e6f2d80eb05405944f87" or (pe.exports("Entry") and pe.exports("InstallM") and pe.exports("InstallS")) or $x1 or 3 of them ) or (5 of them )
}
