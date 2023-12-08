import "pe"

rule Turla_KazuarRAT
{
	meta:
		description = "Detects Turla Kazuar RAT described by DrunkBinary"
		author = "Markus Neis / Florian Roth"
		reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
		date = "2018-04-08"
		hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
		hash2 = "7594fab1aadc4fb08fb9dbb27c418e8bc7f08dadb2acf5533dc8560241ecfc1d"
		hash3 = "4e5a86e33e53931afe25a8cb108f53f9c7e6c6a731b0ef4f72ce638d0ea5c198"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "~1.EXE" wide
		$s2 = "dl32.dll" fullword ascii
		$s3 = "HookProc@" ascii
		$s4 = "0`.wtf" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (pe.imphash()=="682156c4380c216ff8cb766a2f2e8817" or 2 of them )
}
