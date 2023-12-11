rule PassCV_Sabre_Tool_NTScan
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NTscan.EXE" fullword wide
		$x2 = "NTscan Microsoft " fullword wide
		$s1 = "admin$" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 2 of them )
}
