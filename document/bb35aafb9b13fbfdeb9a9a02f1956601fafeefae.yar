rule INDICATOR_PPT_MasterMana
{
	meta:
		description = "Detects known malicious pattern (MasterMana) in PowerPoint documents."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$a1 = "auto_close" ascii nocase
		$a2 = "autoclose" ascii nocase
		$a3 = "auto_open" ascii nocase
		$a4 = "autoopen" ascii nocase
		$vb1 = "\\VBE7.DLL" ascii
		$vb2 = { 41 74 74 72 69 62 75 74 ?? 65 20 56 42 5f 4e 61 6d ?? 65 }
		$clsid = "000204EF-0000-0000-C000-000000000046" wide nocase
		$i1 = "@j.mp/" ascii wide
		$i2 = "j.mp/" ascii wide
		$i3 = "\\pm.j\\\\:" ascii wide
		$i4 = ".zz.ht/" ascii wide
		$i5 = "/pm.j@" ascii wide
		$i6 = "\\pm.j@" ascii wide

	condition:
		uint16(0)==0xcfd0 and 1 of ($i*) and $clsid and 1 of ($a*) and 1 of ($vb*)
}
