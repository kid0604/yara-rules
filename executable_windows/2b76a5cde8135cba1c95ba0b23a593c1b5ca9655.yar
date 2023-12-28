rule tick_xxmm_parts
{
	meta:
		description = "xxmm malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "9374040a9e2f47f7037edaac19f21ff1ef6a999ff98c306504f89a37196074a2"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "C:\\Users\\123\\Desktop\\xxmm3\\"
		$pdb2 = "C:\\Users\\123\\documents\\visual studio 2010\\Projects\\"
		$pdb3 = "C:\\Users\\123\\Documents\\Visual Studio 2010\\Projects\\"
		$sa = "IsLogAllAccess"
		$sb = "allaccess.log"

	condition:
		($pdb1 or $pdb2 or $pdb3 or all of ($s*)) and uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550
}
