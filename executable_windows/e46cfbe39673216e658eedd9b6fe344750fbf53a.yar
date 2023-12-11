import "pe"

rule Borland
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the string 'Borland' in files"
		os = "windows"
		filetype = "executable"

	strings:
		$patternBorland = "Borland" wide ascii

	condition:
		$patternBorland
}
