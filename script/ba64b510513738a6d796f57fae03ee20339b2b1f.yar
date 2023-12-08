rule SUSP_ASPX_PossibleDropperArtifact_Aug21
{
	meta:
		description = "Detects an ASPX file with a non-ASCII header, often a result of MS Exchange drop techniques"
		reference = "Internal Research"
		author = "Max Altgelt"
		date = "2021-08-23"
		score = 60
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Page Language=" ascii nocase
		$fp1 = "Page Language=\"java\"" ascii nocase

	condition:
		filesize <500KB and not uint16(0)==0x4B50 and not uint16(0)==0x6152 and not uint16(0)==0x8b1f and not uint16(0)==0x5A4D and not uint16(0)==0xCFD0 and not uint16(0)==0xC3D4 and not uint16(0)==0x534D and all of ($s*) and not 1 of ($fp*) and ((( uint8(0)<0x20 or uint8(0)>0x7E) and uint8(0)!=0x9 and uint8(0)!=0x0D and uint8(0)!=0x0A and uint8(0)!=0xEF) or (( uint8(1)<0x20 or uint8(1)>0x7E) and uint8(1)!=0x9 and uint8(1)!=0x0D and uint8(1)!=0x0A and uint8(1)!=0xBB) or (( uint8(2)<0x20 or uint8(2)>0x7E) and uint8(2)!=0x9 and uint8(2)!=0x0D and uint8(2)!=0x0A and uint8(2)!=0xBF) or (( uint8(3)<0x20 or uint8(3)>0x7E) and uint8(3)!=0x9 and uint8(3)!=0x0D and uint8(3)!=0x0A) or (( uint8(4)<0x20 or uint8(4)>0x7E) and uint8(4)!=0x9 and uint8(4)!=0x0D and uint8(4)!=0x0A) or (( uint8(5)<0x20 or uint8(5)>0x7E) and uint8(5)!=0x9 and uint8(5)!=0x0D and uint8(5)!=0x0A) or (( uint8(6)<0x20 or uint8(6)>0x7E) and uint8(6)!=0x9 and uint8(6)!=0x0D and uint8(6)!=0x0A) or (( uint8(7)<0x20 or uint8(7)>0x7E) and uint8(7)!=0x9 and uint8(7)!=0x0D and uint8(7)!=0x0A))
}
