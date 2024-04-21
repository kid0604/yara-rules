import "pe"

rule new_documents_2005_iso
{
	meta:
		description = "8099 - file new-documents-2005.iso"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
		date = "2021-11-29"
		hash1 = "1de1336e311ba4ab44828420b4f876d173634670c0b240c6cca5babb1d8b0723"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
		$s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
		$s3 = "SHAREDFI.DLL" fullword ascii
		$s4 = "SharedFiles.dll" fullword wide
		$s5 = "C:\\Users\\User\\Documents" fullword wide
		$s6 = "DragListCtrl.dll" fullword ascii
		$s7 = "MyLinks.dll" fullword wide
		$s8 = "ButtonSkin.dll" fullword wide
		$s9 = "whoami.exe" fullword ascii
		$s10 = " ..\\Windows\\System32\\rundll32.exe" fullword wide
		$s11 = "User (C:\\Users)" fullword wide
		$s12 = "        " fullword ascii
		$s13 = "DOCUMENT.LNK" fullword ascii
		$s14 = "Documents.lnk@" fullword wide
		$s15 = ",System32" fullword wide
		$s16 = " Type Descriptor'" fullword ascii
		$s17 = " constructor or from DllMain." fullword ascii
		$s18 = "  " fullword ascii
		$s19 = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
		$s20 = " Class Hierarchy Descriptor'" fullword ascii

	condition:
		uint16(0)==0x0000 and filesize <2000KB and 1 of ($x*) and 4 of them
}
