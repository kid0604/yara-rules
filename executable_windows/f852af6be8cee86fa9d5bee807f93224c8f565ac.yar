rule INDICATOR_TOOL_EXP_PetitPotam01
{
	meta:
		author = "ditekSHen"
		description = "Detect tool potentially exploiting/attempting PetitPotam"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\pipe\\lsarpc" fullword wide
		$s2 = "\\%s" fullword wide
		$s3 = "ncacn_np" fullword wide
		$s4 = /EfsRpc(OpenFileRaw|EncryptFileSrv|DecryptFileSrv|QueryUsersOnFile|QueryRecoveryAgents|RemoveUsersFromFile|AddUsersToFile)/ wide
		$r1 = "RpcBindingFromStringBindingW" fullword ascii
		$r2 = "RpcStringBindingComposeW" fullword ascii
		$r3 = "RpcStringFreeW" fullword ascii
		$r4 = "RPCRT4.dll" fullword ascii
		$r5 = "NdrClientCall2" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) and 4 of ($r*))
}
