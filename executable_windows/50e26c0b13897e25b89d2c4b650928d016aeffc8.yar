rule QakBot5
{
	meta:
		author = "kevoreilly"
		description = "QakBot WMI anti-anti-vm"
		cape_options = "bp0=$loop+35,action0=skip,count=0"
		packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"
		os = "windows"
		filetype = "executable"

	strings:
		$loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
		$conf = {0F B7 1D [4] B9 [2] 00 00 E8 [4] 8B D3 48 89 45 ?? 45 33 C9 48 8D 0D [4] 4C 8B C0 48 8B F8 E8}

	condition:
		uint16(0)==0x5A4D and any of them
}
