rule hacktool_windows_cobaltstrike_postexploitation
{
	meta:
		description = "Detection of strings in the post-exploitation modules of Cobalt Strike"
		reference = "https://www.cobaltstrike.com/support"
		author = "@javutin, @mimeframe"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "\\devcenter\\aggressor\\external\\"

	condition:
		filesize >10KB and filesize <1000KB and all of ($s*)
}
