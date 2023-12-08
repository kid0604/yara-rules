rule INDICATOR_TOOL_PRI_JuicyPotato
{
	meta:
		author = "ditekSHen"
		description = "Detect JuicyPotato"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\JuicyPotato.pdb" ascii
		$x2 = "JuicyPotato v%s" fullword ascii
		$s1 = "hello.stg" fullword wide
		$s2 = "ppVirtualProcessorRoots" fullword ascii
		$s3 = "Lock already taken" fullword ascii
		$s4 = "[+] authresult %d" fullword ascii
		$s5 = "RPC -> send failed with error: %d" fullword ascii
		$s6 = "Priv Adjust FALSE" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or (5 of ($s*)))
}
