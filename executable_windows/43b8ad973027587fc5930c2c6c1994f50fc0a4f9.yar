rule CN_Honker_Webshell_alt_1
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c85bd09d241c2a75b4e4301091aa11ddd5ad6d59"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii
		$s2 = "Do you want to cancel the file download?" fullword ascii
		$s3 = "Downloading: %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <381KB and all of them
}
