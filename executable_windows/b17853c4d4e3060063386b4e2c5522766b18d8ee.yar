rule EquationGroup_xspy
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <60KB and all of them )
}
