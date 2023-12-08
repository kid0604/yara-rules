import "pe"

rule Check_DriveSize
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
		description = "Rule detects uses of DeviceIOControl to get the drive size"
		os = "windows"
		filetype = "executable"

	strings:
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15}

	condition:
		pe.imports("kernel32.dll","CreateFileA") and pe.imports("kernel32.dll","DeviceIoControl") and $dwIoControlCode and $physicaldrive
}
