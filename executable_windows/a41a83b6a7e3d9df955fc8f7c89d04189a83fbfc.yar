rule Chafer_Packed_Mimikatz
{
	meta:
		description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
		author = "Florian Roth (Nextron Systems) / Markus Neis"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		date = "2018-03-22"
		hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Windows Security Credentials" fullword wide
		$s2 = "Minisoft" fullword wide
		$x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and ( all of ($s*) or $x1)
}
