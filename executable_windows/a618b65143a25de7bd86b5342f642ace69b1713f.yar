import "pe"

rule malware_DtSftDriver
{
	meta:
		description = "Hunt DtSftDriver"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$func0 = {8B 57 10 8B 01 8B 00 57 52 53 FF D0}

	condition:
		( uint16(0)==0x5A4D) and (pe.subsystem==pe.SUBSYSTEM_NATIVE) and pe.imports("FltCreateCommunicationPort","FLTMSR.SYS") and pe.imports("FltRegisterFilter","FLTMSR.SYS") and pe.imports("ZwQueryValueKey","ntoskrnl.exe") and ( filesize >20KB) and ( filesize <300KB) and ( all of ($func*))
}
