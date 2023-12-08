rule MAL_Sharpshooter_Excel4
{
	meta:
		description = "Detects Excel documents weaponized with Sharpshooter"
		author = "John Lambert, Florian Roth"
		reference = "https://github.com/mdsecactivebreach/SharpShooter"
		reference2 = "https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/"
		reference3 = "https://gist.github.com/JohnLaTwC/efab89650d6fcbb37a4221e4c282614c"
		reference4 = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
		date = "2020-03-27"
		score = 70
		hash = "ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
		os = "windows"
		filetype = "document"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = "Excel 4.0 Macros"
		$f1 = "CreateThread" ascii fullword
		$f2 = "WriteProcessMemory" ascii fullword
		$f3 = "Kernel32" ascii fullword
		$concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}

	condition:
		filesize <1000KB and $header_docf at 0 and #concat>10 and $s1 and 2 of ($f*)
}
