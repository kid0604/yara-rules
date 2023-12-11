rule APT_MagicHound_MalMacro
{
	meta:
		description = "Detects malicious macro / powershell in Office document"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
		date = "2017-02-17"
		super_rule = 1
		hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
		hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "powershell.exe " fullword ascii
		$s2 = "CommandButton1_Click" fullword ascii
		$s3 = "URLDownloadToFile" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <8000KB and all of them )
}
