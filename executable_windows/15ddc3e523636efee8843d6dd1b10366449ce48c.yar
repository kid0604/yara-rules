rule EquationGroup_Toolset_Apr17_GetAdmin_LSADUMP_ModifyPrivilege_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "c8b354793ad5a16744cf1d4efdc5fe48d5a0cf0657974eb7145e0088fcf609ff"
		hash2 = "5f06ec411f127f23add9f897dc165eaa68cbe8bb99da8f00a4a360f108bb8741"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\system32\\win32k.sys" fullword wide
		$s2 = "hKeAddSystemServiceTable" fullword ascii
		$s3 = "hPsDereferencePrimaryToken" fullword ascii
		$s4 = "CcnFormSyncExFBC" fullword wide
		$s5 = "hPsDereferencePrimaryToken" fullword ascii
		$op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
		$op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
		$op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and (4 of ($s*) or all of ($op*)))
}
