rule CN_Honker_AspxClient
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2022-12-21"
		score = 70
		hash = "67569a89128f503a459eab3daa2032261507f2d2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\tools\\hashq\\hashq.exe" wide
		$s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" ascii
		$s3 = "\\myshell.mdb" wide
		$s4 = "injectfile" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 3 of them
}
