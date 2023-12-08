rule INDICATOR_TOOL_SharpNoPSExec
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpNoPSExec"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "|-> Service" wide
		$s2 = "authenticated as" wide
		$s3 = "ImpersonateLoggedOnUser failed. Error:{0}" wide
		$s4 = "uPayload" fullword ascii
		$s5 = "pcbBytesNeeded" fullword ascii
		$s6 = "SharpNoPSExec" ascii wide
		$pdb1 = "SharpNoPSExec\\obj\\Debug\\SharpNoPSExec.pdb" ascii
		$pdb2 = "SharpNoPSExec\\obj\\Release\\SharpNoPSExec.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (4 of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}
