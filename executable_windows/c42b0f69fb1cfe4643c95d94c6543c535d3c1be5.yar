rule APT30_Generic_7
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "2415f661046fdbe3eea8cd276b6f13354019b1a6"
		hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
		hash2 = "0263de239ccef669c47399856d481e3361408e90"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Xjapor_*ata" fullword
		$s2 = "Xjapor_o*ata" fullword
		$s4 = "Ouopai" fullword

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
