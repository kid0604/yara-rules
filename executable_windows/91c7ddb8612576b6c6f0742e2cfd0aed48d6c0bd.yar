rule malware_droplink_str
{
	meta:
		description = "malware using dropbox api(TRANSBOX, PLUGBOX)"
		author = "JPCERT/CC Incident Response Group"
		hash = "bdc15b09b78093a1a5503a1a7bfb487f7ef4ca2cb8b4d1d1bdf9a54cdc87fae4"
		hash = "6e5e2ed25155428b8da15ac78c8d87d2c108737402ecba90d70f305056aeabaa"
		os = "windows"
		filetype = "executable"

	strings:
		$data1 = "%u/%u_%08X_%u_%u.jpg" ascii wide
		$data2 = "%u/%u.jpg" ascii wide
		$data3 = "%u/%s" ascii wide
		$data4 = "%u/%u.3_bk.jpg"
		$data5 = "%u/%u.2_bk.jpg" ascii wide
		$data6 = "%u/%u_%08X_%d.jpg" ascii wide
		$data7 = "%s\",\"mode\":\"overwrite" ascii wide
		$data8 = "Dropbox-API-Art-Type:" ascii wide
		$data9 = "/2/files/upload" ascii wide
		$data10 = "Dropbox-API-Arg: {\"path\":\"/" ascii wide
		$data11 = "/oauth2/token" ascii wide
		$data12 = "LoadPlgFromRemote.dll" ascii wide
		$data13 = "FILETRANDLL.dll" ascii wide
		$data14 = "NVIDLA" ascii wide
		$data15 = "start.ini" ascii wide
		$data16 = "RunMain" ascii wide
		$data17 = "cfg.png" ascii wide
		$data18 = "DWrite.dll" ascii wide
		$pdb1 = "\\\\daddev\\office10\\2609.0\\setup\\x86\\ship\\program files\\common files\\microsoft shared\\office10\\1033\\DWINTLO.PDB" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and filesize <1MB and (1 of ($pdb*) or 5 of ($data*))
}
