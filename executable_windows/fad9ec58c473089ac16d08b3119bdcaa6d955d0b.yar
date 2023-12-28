rule Lazarus_Torisma_strvest
{
	meta:
		description = "Torisma in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "7762ba7ae989d47446da21cd04fd6fb92484dd07d078c7385ded459dedc726f9"
		os = "windows"
		filetype = "executable"

	strings:
		$post1 = "ACTION=NEXTPAGE" ascii
		$post2 = "ACTION=PREVPAGE" ascii
		$post3 = "ACTION=VIEW" ascii
		$post4 = "Your request has been accepted. ClientID" ascii
		$password = "ff7172d9c888b7a88a7d77372112d772" ascii
		$vestt = { 4F 70 46 DA E1 8D F6 41 }
		$vestsbox = { 07 56 D2 37 3A F7 0A 52 }
		$vestrns = { 41 4B 1B DD 0D 65 72 EE }

	condition:
		uint16(0)==0x5a4d and ( all of ($post*) or $password or all of ($vest*))
}
