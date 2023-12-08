import "pe"

rule Silence_malware_2
{
	meta:
		description = "Detects malware sample mentioned in the Silence report on Securelist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/the-silence/83009/"
		date = "2017-11-01"
		hash1 = "75b8f534b2f56f183465ba2b63cfc80b7d7d1d155697af141447ec7144c2ba27"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\ScreenMonitorService\\Release\\smmsrv.pdb" ascii
		$x2 = "\\\\.\\pipe\\{73F7975A-A4A2-4AB6-9121-AECAE68AABBB}" fullword ascii
		$s1 = "My Sample Service: ServiceMain: SetServiceStatus returned error" fullword ascii
		$s2 = "\\mss.exe" ascii
		$s3 = "\\out.dat" ascii
		$s4 = "\\mss.txt" ascii
		$s5 = "Default monitor" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="69f3ec173efb6fd3ab5f79e0f8051335" or (1 of ($x*) or 3 of them ))) or (5 of them )
}
