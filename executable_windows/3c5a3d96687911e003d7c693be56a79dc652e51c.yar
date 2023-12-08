rule IISPutScanner
{
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "ADVAPI32.DLL" fullword ascii
		$s4 = "VERSION.DLL" fullword ascii
		$s5 = "WSOCK32.DLL" fullword ascii
		$s6 = "COMCTL32.DLL" fullword ascii
		$s7 = "GDI32.DLL" fullword ascii
		$s8 = "SHELL32.DLL" fullword ascii
		$s9 = "USER32.DLL" fullword ascii
		$s10 = "OLEAUT32.DLL" fullword ascii
		$s11 = "LoadLibraryA" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "VirtualProtect" fullword ascii
		$s14 = "VirtualAlloc" fullword ascii
		$s15 = "VirtualFree" fullword ascii
		$s16 = "ExitProcess" fullword ascii
		$s17 = "RegCloseKey" fullword ascii
		$s18 = "GetFileVersionInfoA" fullword ascii
		$s19 = "ImageList_Add" fullword ascii
		$s20 = "BitBlt" fullword ascii
		$s21 = "ShellExecuteA" fullword ascii
		$s22 = "ActivateKeyboardLayout" fullword ascii
		$s23 = "BBABORT" fullword wide
		$s25 = "BBCANCEL" fullword wide
		$s26 = "BBCLOSE" fullword wide
		$s27 = "BBHELP" fullword wide
		$s28 = "BBIGNORE" fullword wide
		$s29 = "PREVIEWGLYPH" fullword wide
		$s30 = "DLGTEMPLATE" fullword wide
		$s31 = "TABOUTBOX" fullword wide
		$s32 = "TFORM1" fullword wide
		$s33 = "MAINICON" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and filesize >350KB and all of them
}
