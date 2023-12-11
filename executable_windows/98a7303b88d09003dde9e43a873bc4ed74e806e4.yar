import "pe"

rule MALWARE_Win_RomCom_Worker
{
	meta:
		author = "ditekShen"
		description = "Hunt for RomCom worker"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UpdateProcThreadAttribute" fullword ascii
		$s2 = "WriteFile" fullword ascii
		$s3 = "GetAdaptersAddresses" fullword ascii nocase
		$s4 = /inflate\s\d+\.\d+\.\d+\sCopyright/ ascii
		$s5 = "SetHandleInformation" fullword ascii
		$s6 = "PeekNamedPipe" fullword ascii

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and pe.number_of_exports==1 and pe.exports("Main") and all of them
}
