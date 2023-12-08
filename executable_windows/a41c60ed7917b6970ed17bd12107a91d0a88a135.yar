import "pe"

rule WiltedTulip_Zpp
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		modified = "2022-12-21"
		hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
		hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
		hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[ERROR] Error Main -i -s -d -gt -lt -mb" fullword wide
		$x2 = "[ERROR] Error Main -i(with.) -s -d -gt -lt -mb -o -e" fullword wide
		$s1 = "LT Time invalid" fullword wide
		$s2 = "doCompressInNetWorkDirectory" fullword ascii
		$s3 = "files remaining ,total file save = " fullword wide
		$s4 = "$ec996350-79a4-477b-87ae-2d5b9dbe20fd" fullword ascii
		$s5 = "Destinition Directory Not Found" fullword wide
		$s6 = "\\obj\\Release\\ZPP.pdb" ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and (1 of ($x*) or 3 of them )
}
