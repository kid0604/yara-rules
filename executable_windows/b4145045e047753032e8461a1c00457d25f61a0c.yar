import "pe"

rule conti_v3
{
	meta:
		description = "conti_yara - file conti_v3.dll"
		author = "pigerlin"
		reference = "https://thedfirreport.com"
		date = "2021-05-09"
		hash1 = "8391dc3e087a5cecba74a638d50b771915831340ae3e027f0bb8217ad7ba4682"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s2 = "conti_v3.dll" fullword ascii
		$s3 = " <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s4 = " Type Descriptor'" fullword ascii
		$s5 = "operator co_await" fullword ascii
		$s6 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		$s8 = " Base Class Descriptor at (" fullword ascii
		$s9 = " Class Hierarchy Descriptor'" fullword ascii
		$s10 = " Complete Object Locator'" fullword ascii
		$s11 = " delete[]" fullword ascii
		$s12 = " </trustInfo>" fullword ascii
		$s13 = "__swift_1" fullword ascii
		$s15 = "__swift_2" fullword ascii
		$s19 = " delete" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
