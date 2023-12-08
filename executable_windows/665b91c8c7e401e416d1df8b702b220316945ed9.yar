rule dubseven_file_set
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for service files loading UP007"
		os = "windows"
		filetype = "executable"

	strings:
		$file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
		$file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
		$file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
		$file4 = "\\Microsoft\\Internet Explorer\\main.dll"
		$file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
		$file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
		$file7 = "\\Microsoft\\Internet Explorer\\mon"
		$file8 = "\\Microsoft\\Internet Explorer\\runas.exe"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and 3 of ($file*)
}
