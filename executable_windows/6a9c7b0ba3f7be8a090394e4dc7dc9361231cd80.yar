rule Malware_QA_get_The_FucKinG_IP
{
	meta:
		description = "VT Research QA uploaded malware - file get The FucKinG IP.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "7b2c04e384919075be96e3412d92c14fc1165d1bc7556fd207488959c5c4d2f7"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\Mdram ahmed\\AppData"
		$x2 = "\\Local\\Temporary Projects\\get The FucKinG IP\\" ascii
		$x3 = "get The FucKinG IP.exe" fullword wide
		$x4 = "get ip by mdr3m" fullword wide
		$x5 = "MDR3M kik: Mdr3mhm" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 1 of ($x*)) or (2 of them )
}
