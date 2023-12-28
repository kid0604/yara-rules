rule malware_NimFilecoder
{
	meta:
		description = "NimCopycatLoader malware in human-operated ransomware attack"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "9a10ead4b8971b830daf1d0b7151462fb6cc379087b65b3013c756db3ce87118"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = ":wtfbbq" ascii wide
		$lib = "clr.nim" ascii wide

	condition:
		uint16(0)==0x5A4D and all of them
}
