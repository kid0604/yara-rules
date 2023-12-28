rule BlackTech_Bifrose_elf
{
	meta:
		description = "ELF Bifrose in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "0478fe3022b095927aa630ae9a00447eb024eb862dbfce3eaa3ca6339afec9c1"
		os = "linux"
		filetype = "executable"

	strings:
		$msg1 = { 30 7C 00 31 7C 00 }
		$msg2 = { 35 2E 30 2E 30 2E 30 7C 00 }
		$msg3 = "%c1%s%c3D%c4%u-%.2u-%.2u %.2u:%.2u" ascii
		$msg4 = "%c2%s%c3%u%c4%u-%.2u-%.2u %.2u:%.2u" ascii
		$msg5 = "RecvData 4 bytes header error!" ascii
		$msg6 = "Deal with error! ret==0 goto error!" ascii
		$msg7 = "send data over..." ascii
		$msg8 = "cfgCount=%d" ascii
		$msg9 = "%x : %s %d" ascii
		$msg10 = "recvData timeout :%d" ascii

	condition:
		uint32(0)==0x464C457F and 5 of them
}
