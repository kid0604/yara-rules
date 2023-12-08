import "pe"

rule PolyCryptPE214b215JLabSoftwareCreationshoep
{
	meta:
		author = "malware-lu"
		description = "Detects PolyCrypt PE214b215JLabSoftwareCreationshoep malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }

	condition:
		$a0
}
