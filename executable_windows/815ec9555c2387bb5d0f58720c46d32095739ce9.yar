rule DMALocker : ransom
{
	meta:
		Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
		ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
		Author = "SadFud"
		Date = "30/05/2016"
		description = "Detects DMA Locker ransomware versions 1.0 to 4.0"
		os = "windows"
		filetype = "executable"

	strings:
		$uno = { 41 42 43 58 59 5a 31 31 }
		$dos = { 21 44 4d 41 4c 4f 43 4b }
		$tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
		$cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }

	condition:
		any of them
}
