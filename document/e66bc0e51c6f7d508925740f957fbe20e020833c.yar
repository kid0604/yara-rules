rule INDICATOR_RTF_MultiExploit_Embedded_Files
{
	meta:
		description = "Detects RTF documents potentially exploting multiple vulnerabilities and embeding next stage scripts and/or binaries"
		author = "ditekSHen"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$eq1 = "02ce020000000000c000000000000046" ascii nocase
		$eq2 = { 02ce020000000000c000000000000046 }
		$ole2link1 = "03000000000000c000000000000046" ascii nocase
		$ole2link2 = { (36|34) (66|46) (36|34) (63|43) (36|34) 35 33 32 (36|34) (63|43) (36|34) 39 (36|34) (65|45) (36|34) (62|42) }
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\mmath" ascii
		$pkg = { (70|50) (61|41) (63|43) (6b|4b) (61|41) (67|47) (65|45) }
		$emb_exe = { 3265 (3635|3435) (3738|3538) (3635|3435) 3030 }
		$emb_scr = { 3265 (3733|3533) (3633|3433) (3532|3732) 3030 }
		$emb_dll = { 3265 (3634|3434) (3663|3463) (3663|3463) 3030 }
		$emb_doc = { 3265 (3634|3434) (3666|3466) (3633|3433) 3030 }
		$emb_bat = { 3265 (3632|3432) (3631|3431) (3734|3534) 3030 }
		$emb_sct = { 3265 (3733|3533) (3633|3433) (3734|3534) 3030 }
		$emb_txt = { 3265 (3734|3534) (3738|3538) (3734|3534) 3030 }
		$emb_psw = { 3265 (3730|3530) (3733|3533) 313030 }

	condition:
		uint32(0)==0x74725c7b and (1 of ($eq*) or 1 of ($ole2link*)) and $pkg and 2 of ($obj*) and 1 of ($emb*)
}
