rule arpsniffer
{
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii
		$s5 = "packet.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <120KB and all of them
}
