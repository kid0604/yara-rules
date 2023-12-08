rule Chafer_Exploit_Copyright_2017
{
	meta:
		description = "Detects Oilrig Internet Server Extension with Copyright (C) 2017 Exploit"
		author = "Markus Neis"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		date = "2018-03-22"
		hash1 = "cdac69caad8891c5e1b8eabe598c869674dee30af448ce4e801a90eb79973c66"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "test3 Internet Server Extension" fullword wide
		$x2 = "Copyright (C) 2017 Exploit" fullword wide
		$a1 = "popen() failed!" fullword ascii
		$a2 = "cmd2cmd=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or all of ($a*))
}
