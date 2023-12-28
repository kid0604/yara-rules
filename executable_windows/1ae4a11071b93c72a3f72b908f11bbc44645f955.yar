rule darkhotel_srdfqm_strings
{
	meta:
		description = "darkhotel srdfqm.exe"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "b7f9997b2dd97086343aa21769a60fb1d6fbf2d5cc6386ee11f6c52e6a1a780c"
		hash2 = "26a01df4f26ed286dbb064ef5e06ac7738f5330f6d60078c895d49e705f99394"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "BadStatusLine (%s)" ascii fullword
		$a2 = "UnknownProtocol (%s)" ascii fullword
		$a3 = "Request already issued" ascii fullword
		$a4 = "\\Microsoft\\Network\\" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( filesize <800KB) and ( all of them )
}
