rule EquationGroup_Toolset_Apr17_xxxRIDEAREA
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "214b0de83b04afdd6ad05567825b69663121eda9e804daff9f2da5554ade77c6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
		$x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
		$x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
		$x4 = "Load and execute implant within the existing thread" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
