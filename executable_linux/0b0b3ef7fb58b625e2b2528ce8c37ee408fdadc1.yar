rule SUSP_ELF_SPARC_Hunting_SBZ_UniqueStrings
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for performance reasons"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "<%u>[%s] Event #%u: "
		$s2 = "lprc:%08X" ascii fullword
		$s3 = "diuXxobB"
		$s4 = "CHM_FW"

	condition:
		2 of ($*)
}
