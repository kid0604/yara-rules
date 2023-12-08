import "pe"

rule Winnti_malware_StreamPortal_Gen
{
	meta:
		description = "Detects a Winnti malware - Streamportal"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash3 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Proxies destination address/port for TCP" fullword wide
		$s3 = "\\Device\\StreamPortal" wide
		$s4 = "Transport-Data Proxy Sub-Layer" fullword wide
		$s5 = "Cookie: SN=" fullword ascii
		$s6 = "\\BaseNamedObjects\\_transmition_synchronization_" wide
		$s17 = "NTOSKRNL.EXE" fullword wide
		$s19 = "FwpsReferenceNetBufferList0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <275KB and all of them
}
