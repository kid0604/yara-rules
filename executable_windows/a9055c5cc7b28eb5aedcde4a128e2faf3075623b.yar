import "pe"

rule Check_VmTools
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
		description = "Checks for the existence of VmTools reg key"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide

	condition:
		any of them
}
