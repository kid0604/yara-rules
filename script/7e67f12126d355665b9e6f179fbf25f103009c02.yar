rule Contains_VBE_File : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detect a VBE file inside a byte sequence"
		method = "Find string starting with #@~^ and ending with ^#~@"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$vbe = /#@~\^.+\^#~@/

	condition:
		$vbe
}
