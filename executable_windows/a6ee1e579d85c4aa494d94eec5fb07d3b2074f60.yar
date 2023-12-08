rule INDICATOR_TOOL_EXFIL_SharpBox
{
	meta:
		author = "ditekSHen"
		description = "Detect SharpBox, C# tool for compressing, encrypting, and exfiltrating data to Dropbox using the Dropbox API"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UploadData" fullword ascii
		$s2 = "isAttached" fullword ascii
		$s3 = "DecryptFile" fullword ascii
		$s4 = "set_dbxPath" fullword ascii
		$s5 = "set_dbxToken" fullword ascii
		$s6 = "set_decrypt" fullword ascii
		$s7 = "GeneratePass" fullword ascii
		$s8 = "FileUploadToDropbox" fullword ascii
		$s9 = "\\SharpBox.pdb" ascii
		$s10 = "https://content.dropboxapi.com/2/files/upload" fullword wide
		$s12 = "Dropbox-API-Arg: {\"path\":" wide
		$s13 = "X509Certificate [{0}] Policy Error: '{1}'" fullword wide

	condition:
		uint16(0)==0x5a4d and 7 of them
}
