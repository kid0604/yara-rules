import "pe"

rule MALWARE_Win_MeterpreterStager
{
	meta:
		author = "ditekSHen"
		description = "Detects Meterpreter stager payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PAYLOAD:" fullword ascii
		$s2 = "AQAPRQVH1" fullword ascii
		$s3 = "ws2_32" fullword ascii
		$s4 = "KERNEL32.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them and filesize <100KB
}
