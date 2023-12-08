import "pe"

rule INDICATOR_EXE_Packed_AgileDotNet
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Agile.NET / CliSecure"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "AgileDotNetRT" fullword ascii
		$x2 = "AgileDotNetRT64" fullword ascii
		$x3 = "<AgileDotNetRT>" fullword ascii
		$x4 = "AgileDotNetRT.dll" fullword ascii
		$x5 = "AgileDotNetRT64.dll" fullword ascii
		$x6 = "get_AgileDotNet" ascii
		$x7 = "useAgileDotNetStackFrames" fullword ascii
		$x8 = "AgileDotNet." ascii
		$x9 = "://secureteam.net/webservices" ascii
		$x10 = "AgileDotNetProtector." ascii
		$s1 = "Callvirt" fullword ascii
		$s2 = "_Initialize64" fullword ascii
		$s3 = "_AtExit64" fullword ascii
		$s4 = "DomainUnload" fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*))
}
