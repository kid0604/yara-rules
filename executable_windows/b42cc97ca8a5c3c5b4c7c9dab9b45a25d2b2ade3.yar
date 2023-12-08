rule CN_Tools_VNCLink
{
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <580KB and 2 of them
}
