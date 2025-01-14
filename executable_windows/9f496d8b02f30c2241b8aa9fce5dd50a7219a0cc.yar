rule APT10_ANEL_str
{
	meta:
		description = "ANEL malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "08533b6ba7801e6393be661190394eb0605cad465438fbc9806058ae8864468e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dll_size %Iu bytes, compress_size %Iu bytes, dllhash 0x%08x"
		$s2 = "The file does not exist on this server!"
		$s3 = "WARNING: loading PE file without .reloc section!"
		$s4 = "x86 version supports x86 shellcode only!"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 3 of them
}
