import "pe"

rule tdr615_exe
{
	meta:
		description = "Cobalt Strike on beachhead: tdr615.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-07-07"
		hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$a2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii
		$b1 = "ealagi@aol.com0" fullword ascii
		$b2 = "operator co_await" fullword ascii
		$b3 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii
		$b4 = "RtlExitUserThrebNtFlushInstruct" fullword ascii
		$c1 = "Jersey City1" fullword ascii
		$c2 = "Mariborska cesta 971" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and any of ($a*) and 2 of ($b*) and any of ($c*)
}
