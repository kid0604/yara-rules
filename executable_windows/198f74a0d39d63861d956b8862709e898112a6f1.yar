import "pe"

rule Setup2GoInstallerStub
{
	meta:
		author = "malware-lu"
		description = "Detects Setup2Go installer stub"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }

	condition:
		$a0
}
