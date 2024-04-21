rule BlackTech_IconDown_resource
{
	meta:
		description = "detect IconDown"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "f6494698448cdaf6ec0ed7b3555521e75fac5189fa3c89ba7b2ad492188005b4"
		os = "windows"
		filetype = "executable"

	strings:
		$key = {00 13 87 33 00 90 06 19}

	condition:
		( uint16(0)!=0x5A4D) and ( filesize <5MB) and $key
}
