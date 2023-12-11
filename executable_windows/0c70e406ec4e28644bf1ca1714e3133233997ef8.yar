import "pe"

rule INDICATOR_EXE_Packed_GEN01
{
	meta:
		author = "ditekSHen"
		description = "Detect packed .NET executables. Mostly AgentTeslaV4."
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "com.apple.Safari" fullword ascii
		$c2 = "Unable to resolve HTTP prox" fullword ascii
		$c3 = "rotcetorP rekciP laitnederC swodniW$" fullword ascii
		$c4 = "laitnederC drowssaP beW swodniW$" fullword ascii
		$s1 = "Accounts" fullword wide
		$s2 = "logins" fullword wide
		$s3 = "sha512" fullword wide
		$s4 = "credential" fullword wide

	condition:
		uint16(0)==0x5a4d and 2 of ($c*) and all of ($s*)
}
