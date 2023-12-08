rule Stuxnet_Malware_4
{
	meta:
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
		hash2 = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
		$x2 = "MRxCls.sys" fullword wide
		$x3 = "MRXNET.Sys" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them ) or ( all of them )
}
