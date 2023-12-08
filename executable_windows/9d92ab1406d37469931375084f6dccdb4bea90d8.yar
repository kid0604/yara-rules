rule Dos_netstat
{
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "w03a2409.dll" fullword ascii
		$s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide
		$s2 = "Administrative Status  = %1!u!" fullword wide
		$s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
