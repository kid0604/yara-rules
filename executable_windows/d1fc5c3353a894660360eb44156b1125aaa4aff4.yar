rule BypassUac_EXE
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Wole32.dll" wide
		$s3 = "System32\\migwiz" wide
		$s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
		$s5 = "Elevation:Administrator!new:" wide
		$s6 = "BypassUac" wide

	condition:
		all of them
}
