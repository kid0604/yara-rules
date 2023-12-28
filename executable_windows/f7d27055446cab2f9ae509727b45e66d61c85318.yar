rule darkhotel_lnk_strings
{
	meta:
		description = "detect suspicious lnk file"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "lnk file search"
		reference = "internal research"
		hash1 = "cd431575e46b80237e84cc38d3b0bc6dcd676735c889539b5efa06cec22f0560"
		hash2 = "f0d9acec522aafce3ba1c90c8af0146399a6aa74427d1cbd010a4485aacd418d"
		hash3 = "decafff59011282484d47712eec5c11cac7e17b0a5026e54d69c05e3e593ee48"
		os = "windows"
		filetype = "executable"

	strings:
		$hostname1 = "win-j1m3n7bfrbl" ascii fullword
		$hostname2 = "win-fe8b6nec4ks" ascii fullword
		$a1 = "cmd.exe" wide ascii
		$a2 = "mshta.exe" wide ascii
		$b1 = "TVqQAAMAAAAEAAAA" ascii

	condition:
		( uint16(0)==0x004C) and (( filesize <1MB) and ( filesize >200KB)) and ((1 of ($hostname*)) or ((1 of ($a*)) and ($b1)))
}
