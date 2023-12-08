rule SUSP_Excel4Macro_AutoOpen
{
	meta:
		description = "Detects Excel4 macro use with auto open / close"
		author = "John Lambert @JohnLaTwC"
		date = "2020-03-26"
		score = 50
		hash = "2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
		os = "windows"
		filetype = "document"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = "Excel" fullword
		$Auto_Open = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
		$Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

	condition:
		filesize <3000KB and $header_docf at 0 and $s1 and any of ($Auto_*)
}
