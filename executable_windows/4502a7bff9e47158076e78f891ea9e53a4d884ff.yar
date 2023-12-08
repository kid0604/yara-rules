rule APT30_Generic_B
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
		hash2 = "29395c528693b69233c1c12bef8a64b3"
		hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
		hash4 = "550459b31d8dabaad1923565b7e50242"
		hash5 = "65232a8d555d7c4f7bc0d7c5da08c593"
		hash6 = "853a20f5fc6d16202828df132c41a061"
		hash7 = "ed151602dea80f39173c2f7b1dd58e06"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Moziea/4.0" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
