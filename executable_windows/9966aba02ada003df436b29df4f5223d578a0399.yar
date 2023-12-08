rule BypassUac_3
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide

	condition:
		3 of them
}
