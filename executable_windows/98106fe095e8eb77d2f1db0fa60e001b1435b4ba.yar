rule malware_vboxuserRAT
{
	meta:
		description = "Hunt vboxuserRAT"
		author = "JPCERT/CC Incident Response Group"
		hash = "47FB80593A1924AE4351C3A8C9EE9F1F365267719531387E88A4A82000088E48"
		os = "windows"
		filetype = "executable"

	strings:
		$cmdfunc1 = { 65 78 65 5F 64 6C 6C 5F }
		$cmdfunc2 = { 72 75 6E 64 6C 6C 33 32 }
		$cmdfunc3 = { 73 68 65 6C 6C 5F 63 6C }
		$cmdfunc4 = { 72 75 6E 5F 77 69 74 68 }
		$cmdfunc5 = { 73 68 65 6C 6C 5F 73 79 }
		$cmdstr1 = "run_dll_from_memory" ascii
		$cmdstr2 = "run_exe_from_memory" ascii

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3c))==0x00004550) and ( filesize >3MB) and ( filesize <10MB) and (3 of ($cmdfunc*)) and (1 of ($cmdstr*))
}
