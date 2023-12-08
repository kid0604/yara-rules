rule INDICATOR_PUB_MSIEXEC_Remote
{
	meta:
		description = "detects VB-enable Microsoft Publisher files utilizing Microsoft Installer to retrieve remote files and execute them"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "Microsoft Publisher" ascii
		$s2 = "msiexec.exe" ascii
		$s3 = "Document_Open" ascii
		$s4 = "/norestart" ascii
		$s5 = "/i http" ascii
		$s6 = "Wscript.Shell" fullword ascii
		$s7 = "\\VBE6.DLL#" wide

	condition:
		uint16(0)==0xcfd0 and 6 of them
}
