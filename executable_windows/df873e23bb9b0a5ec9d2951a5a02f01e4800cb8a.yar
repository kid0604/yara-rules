rule INDICATOR_KB_ID_QakBot
{
	meta:
		author = "ditekShen"
		description = "Detects QakBot executables with specific email addresses found in the code signing certificate"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "hutter.s94@yahoo.com" ascii wide nocase
		$s2 = "andrej.vrear@aol.com" ascii wide nocase
		$s3 = "klaus.pedersen@aol.com" ascii wide nocase
		$s4 = "a.spendl@aol.com" ascii wide nocase
		$s5 = "mjemec@aol.com" ascii wide nocase
		$s6 = "robert.sijanec@yahoo.com" ascii wide nocase
		$s7 = "mitja.vidovi@aol.com" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}
