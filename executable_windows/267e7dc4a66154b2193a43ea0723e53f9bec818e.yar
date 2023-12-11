rule INDICATOR_TOOL_SCR_Amady
{
	meta:
		author = "ditekSHen"
		description = "Detects screenshot stealer DLL. Dropped by Amadey"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "User-Agent: Uploador" fullword ascii
		$s2 = "Content-Disposition: form-data; name=\"data\"; filename=\"" fullword ascii
		$s3 = "WebUpload" fullword ascii
		$s4 = "Cannot assign a %s to a %s%List does not allow duplicates ($0%x)%String" wide
		$s5 = "scr.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 4 of them
}
