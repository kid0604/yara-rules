rule bumblebee_13842_wSaAHJzLLT_exe
{
	meta:
		description = "BumbleBee - file wSaAHJzLLT.exe"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
		date = "2022-11-13"
		hash1 = "df63149eec96575d66d90da697a50b7c47c3d7637e18d4df1c24155abacbc12e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ec2-3-16-159-37.us-east-2.compute.amazonaws.com" fullword ascii
		$s2 = "PAYLOAD:" fullword ascii
		$s3 = "AQAPRQVH1" fullword ascii
		$s4 = "AX^YZAXAYAZH" fullword ascii
		$s5 = "/bIQRfeCGXT2vja6Pzf8uZAWzlUMGzUHDk" fullword ascii
		$s6 = "SZAXM1" fullword ascii
		$s7 = "SYj@ZI" fullword ascii
		$s8 = "@.nbxi" fullword ascii
		$s9 = "Rich}E" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
