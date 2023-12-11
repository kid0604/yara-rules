rule GuloaderB
{
	meta:
		author = "kevoreilly"
		description = "Guloader bypass 2021 Edition"
		cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret:2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,bp3=$trap2+7,action3=skip"
		packed = "9ec05fd611c2df63c12cc15df8e87e411f358b7a6747a44d4a320c01e3367ca8"
		os = "windows"
		filetype = "executable"

	strings:
		$trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
		$trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
		$antihook = {FF 34 08 [0-360] 8F 04 0B [0-360] 83 F9 18 [0-460] FF E3}
		$trap2 = {83 BD 9C 00 00 00 00 0F 85 [2] 00 00}

	condition:
		3 of them
}
