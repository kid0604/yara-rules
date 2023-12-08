import "pe"

rule MALWARE_Win_UDPRat
{
	meta:
		author = "ditekSHen"
		description = "Detects UDPRat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\code\\UDP\\Client\\" ascii
		$s2 = "ssdp:discover" ascii
		$s3 = ": Device:" ascii
		$s4 = "for the SNMP U encountered" ascii
		$s5 = "privat:InternetGatewayelink" fullword ascii
		$s6 = "schemas A jet error was" ascii
		$s7 = "msidentity" fullword ascii
		$s8 = "microsoftonliser-based Securi" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
