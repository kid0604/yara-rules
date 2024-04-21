rule AgentTeslaV3JIT
{
	meta:
		author = "ClaudioWayne"
		description = "AgentTesla V3 JIT native string decryption"
		cape_options = "bp0=$decode+20,count=0,action0=string:eax+8,typestring=AgentTesla Strings,no-logs=2"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {8B C8 57 FF 75 08 8B [5] 8B 01 8B 40 3C FF [2] 8B F0 B8 03 00 00 00}

	condition:
		all of them
}
