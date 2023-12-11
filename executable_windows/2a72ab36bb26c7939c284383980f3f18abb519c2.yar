import "pe"

rule FE_APT_9002
{
	meta:
		Author = "FireEye Labs"
		Date = "2013/11/10"
		Description = "Strings inside"
		Reference = "Useful link"
		description = "Detects strings inside"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$a = "rat_UnInstall" wide ascii

	condition:
		($mz at 0) and $a
}
