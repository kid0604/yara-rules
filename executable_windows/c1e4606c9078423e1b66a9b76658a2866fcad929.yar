import "pe"

rule MALWARE_Win_MediaPI
{
	meta:
		author = "ditekSHen"
		description = "Detects MediaPI"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SomeFunction" ascii
		$s2 = "\"stealth" ascii
		$s3 = "\"ServAddr" ascii
		$s4 = "\"ServPort" ascii
		$s5 = "\"ServIp" ascii
		$s6 = "\"wsaData" ascii
		$s7 = "\"-socket" ascii

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and ((6 of them ) or (3 of them and pe.exports("SomeFunction")))
}
