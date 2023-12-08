rule ZXshell2_0_rar_Folder_nc
{
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "WSOCK32.dll"
		$s1 = "?bSUNKNOWNV"
		$s7 = "p@gram Jm6h)"
		$s8 = "ser32.dllCONFP@"

	condition:
		all of them
}
