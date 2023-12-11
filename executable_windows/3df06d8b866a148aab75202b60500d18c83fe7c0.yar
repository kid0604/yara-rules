rule CN_Honker_sig_3389_2_3389
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3389.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "48d1974215e5cb07d1faa57e37afa91482b5a376"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\" ascii
		$s2 = "net user guest /active:yes" fullword ascii
		$s3 = "\\Microsoft Word.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and all of them
}
