rule Lightweight_Backdoor1
{
	meta:
		description = "Detects the presence of Lightweight Backdoor1"
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = "NetMgStart"
		$STR2 = "Netmgmt.srg"

	condition:
		( uint16(0)==0x5A4D) and all of them
}
