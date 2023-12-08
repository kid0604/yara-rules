rule ProPort_zip_Folder_ProPort
{
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"

	condition:
		all of them
}
