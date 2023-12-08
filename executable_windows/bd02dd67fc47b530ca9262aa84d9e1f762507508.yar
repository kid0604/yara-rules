rule WindowsCredentialEditor
{
	meta:
		description = "Windows Credential Editor"
		threat_level = 10
		score = 90
		os = "windows"
		filetype = "executable"

	strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"

	condition:
		$a or $b
}
