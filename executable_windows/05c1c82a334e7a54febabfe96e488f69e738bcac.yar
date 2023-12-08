rule DMALocker4 : ransom
{
	meta:
		Description = "Deteccion del ransomware DMA Locker version 4.0"
		ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
		Author = "SadFud"
		Date = "30/05/2016"
		Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
		description = "Deteccion del ransomware DMA Locker version 4.0"
		os = "windows"
		filetype = "executable"

	strings:
		$clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }

	condition:
		$clave
}
