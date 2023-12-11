rule PassCV_Sabre_Malware_Signing_Cert
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		score = 50
		hash1 = "7c32885c258a6d5be37ebe83643f00165da3ebf963471503909781540204752e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WOODTALE TECHNOLOGY INC" ascii
		$s2 = "Flyingbird Technology Limited" ascii
		$s3 = "Neoact Co., Ltd." ascii
		$s4 = "AmazGame Age Internet Technology Co., Ltd" ascii
		$s5 = "EMG Technology Limited" ascii
		$s6 = "Zemi Interactive Co., Ltd" ascii
		$s7 = "337 Technology Limited" ascii
		$s8 = "Runewaker Entertainment0" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and 1 of them )
}
