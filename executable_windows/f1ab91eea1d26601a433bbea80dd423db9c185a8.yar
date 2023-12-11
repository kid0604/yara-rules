rule PassCV_Sabre_Malware_3
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "28c7575b2368a9b58d0d1bf22257c4811bd3c212bd606afc7e65904041c29ce1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NXKILL" fullword wide
		$s1 = "2OLE32.DLL" fullword ascii
		$s2 = "localspn.dll" fullword wide
		$s3 = "!This is a Win32 program." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <8000KB and $x1 and 2 of ($s*))
}
