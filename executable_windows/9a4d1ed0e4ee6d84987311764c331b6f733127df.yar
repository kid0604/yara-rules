import "pe"

rule MALWARE_Win_NetWire
{
	meta:
		author = "ditekSHen"
		description = "Detects NetWire RAT"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SOFTWARE\\NetWire" fullword ascii
		$x2 = { 4e 65 74 57 69 72 65 00 53 4f 46 54 57 41 52 45 5c 00 }
		$s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
		$s2 = "filenames.txt" fullword ascii
		$s3 = "GET %s HTTP/1.1" fullword ascii
		$s4 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
		$s5 = "Host.exe" fullword ascii
		$s6 = "-m \"%s\"" fullword ascii
		$g1 = "HostId" fullword ascii
		$g2 = "History" fullword ascii
		$g3 = "encrypted_key" fullword ascii
		$g4 = "Install Date" fullword ascii
		$g5 = "hostname" fullword ascii
		$g6 = "encryptedUsername" fullword ascii
		$g7 = "encryptedPassword" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($x*) or (1 of ($x*) and 2 of ($s*)) or ( all of ($g*) and (2 of ($s*) or 1 of ($x*))))
}
