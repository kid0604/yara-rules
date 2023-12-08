rule Mithril_dllTest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"

	condition:
		all of them
}
