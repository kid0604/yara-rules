rule INDICATOR_TOOL_MEM_mXtract
{
	meta:
		author = "ditekSHen"
		description = "Detects mXtract, a linux-based tool that dumps memory for offensive pentration testing and can be used to scan memory for private keys, ips, and passwords using regexes."
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "_ZN18process_operations10get_rangesEv" fullword ascii
		$s2 = "_ZN4misc10write_dumpESsSs" fullword ascii
		$s3 = "_ZTVNSt8__detail13_Scanner_baseE" fullword ascii
		$s4 = "Running as root is recommended as not all PIDs will be scanned" fullword ascii
		$s5 = "ERROR ATTACHING TO PROCESS" fullword ascii
		$s6 = "ERROR SCANNING MEMORY RANGE" fullword ascii

	condition:
		( uint32(0)==0x464c457f or uint16(0)==0x457f) and 3 of them
}
