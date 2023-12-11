rule Msfpayloads_msf_svc
{
	meta:
		description = "Metasploit Payloads - file msf-svc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PAYLOAD:" fullword ascii
		$s2 = ".exehll" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
