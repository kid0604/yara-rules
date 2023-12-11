rule Codoso_CustomTCP_3
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DnsApi.dll" fullword ascii
		$s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
		$s3 = "CONNECT %s:%d hTTP/1.1" ascii
		$s4 = "CONNECT %s:%d HTTp/1.1" ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
		$s6 = "iphlpapi.dll" ascii
		$s7 = "%systemroot%\\Web\\" ascii
		$s8 = "Proxy-Authorization: Negotiate %s" ascii
		$s9 = "CLSID\\{%s}\\InprocServer32" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 5 of them ) or 7 of them
}
