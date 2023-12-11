import "pe"

rule PE_File_pyinstaller
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detect PE file produced by pyinstaller"
		reference = "https://isc.sans.edu/diary/21057"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "pyi-windows-manifest-filename"

	condition:
		pe.number_of_resources>0 and $a
}
