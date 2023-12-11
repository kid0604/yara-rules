rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_3_0
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "49b311add0940cf183e3c7f3a41ea6e516bf8992"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "explorer.exe http://bbs.yesmybi.net" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s9 = "CryptGenRandom" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <395KB and all of them
}
