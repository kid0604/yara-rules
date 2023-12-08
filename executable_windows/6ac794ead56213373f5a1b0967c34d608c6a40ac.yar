rule PassCV_Sabre_Malware_4
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "27463bcb4301f0fdd95bc10bf67f9049e161a4e51425dac87949387c54c9167f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "QWNjZXB0On" fullword ascii
		$s2 = "VXNlci1BZ2VudDogT" fullword ascii
		$s3 = "dGFzay5kbnME3luLmN" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
