rule VBScript_Favicon_File
{
	meta:
		description = "VBScript cloaked as Favicon file used in Leviathan incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		modified = "2023-01-06"
		hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "myxml = '<?xml version=\"\"1.0\"\" encoding=\"\"UTF-8\"\"?>';myxml = myxml +'<root>" ascii
		$x2 = ".Run \"taskkill /im mshta.exe" ascii
		$x3 = "<script language=\"VBScript\">Window.ReSizeTo 0, 0 : Window.moveTo -2000,-2000 :" ascii
		$s1 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") &" ascii
		$s2 = ".ExpandEnvironmentStrings(\"%temp%\") & " ascii

	condition:
		filesize <100KB and ( uint16(0)==0x733c and 1 of ($x*)) or (3 of them )
}
