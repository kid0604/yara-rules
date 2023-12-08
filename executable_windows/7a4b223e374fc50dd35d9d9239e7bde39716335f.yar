import "pe"

rule MAL_RedLeaves_Apr18_1
{
	meta:
		description = "Detects RedLeaves malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
		date = "2018-05-01"
		hash1 = "f6449e255bc1a9d4a02391be35d0dd37def19b7e20cfcc274427a0b39cb21b7b"
		hash2 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"
		hash3 = "d956e2ff1b22ccee2c5d9819128103d4c31ecefde3ce463a6dea19ecaaf418a1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.imphash()=="7a861cd9c495e1d950a43cb708a22985" or pe.imphash()=="566a7a4ef613a797389b570f8b4f79df")
}
