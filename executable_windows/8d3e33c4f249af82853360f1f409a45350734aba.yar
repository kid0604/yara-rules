rule rknt_zip_Folder_RkNT
{
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f97386dfde148942b7584aeb6512b85"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"

	condition:
		all of them
}
