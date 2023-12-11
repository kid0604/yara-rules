rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
