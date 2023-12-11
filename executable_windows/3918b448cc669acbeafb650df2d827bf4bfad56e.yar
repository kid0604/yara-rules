import "pe"

rule Slingshot_APT_Malware_2
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		hash1 = "2a51ef6d115daa648ddd57d1e4480f5a18daf40986bfde32aab19349aa010e67"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\\\?\\c:\\RECYCLER\\S-1-5-21-2225084468-623340172-1005306204-500\\INFO5" fullword wide
		$x_slingshot = {09 46 BE 57 42 DD 70 35 5E }
		$s1 = "Opening service %s for stop access failed.#" fullword wide
		$s2 = "LanMan setting <%s> is ignored because system has a higher value already." fullword wide
		$s3 = "\\DosDevices\\amxpci" wide
		$s4 = "lNTLMqSpPD" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 4 of them )
}
