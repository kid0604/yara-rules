rule IP_Stealing_Utilities
{
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"

	condition:
		all of them
}
