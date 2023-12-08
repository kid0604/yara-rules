rule Retefe
{
	meta:
		author = "bartblaze"
		description = "Retefe"
		os = "windows"
		filetype = "executable"

	strings:
		$string0 = "01050000"
		$string1 = "00000000"
		$string2 = "5061636b61676500"
		$string3 = "000000000000000000000000000000000000000000000000000000000000000000000000000000"
		$string4 = "{\\stylesheet{ Normal;}{\\s1 heading 1;}{\\s2 heading 2;}}"
		$string5 = "02000000"

	condition:
		5 of them
}
